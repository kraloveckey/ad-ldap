#!/usr/bin/env python3
"""
Extract BitLocker recovery keys from AD using msldap 0.5.15.

Features
- Impacket-style target: domain.tld/username[:password]@OptionalDCFQDN
- Auth modes: NTLM (password, --no-pass, --hashes), Kerberos (-k with ccache/password/RC4/AES)
- Scheme selection: --scheme {ldap, ldaps} (default ldaps)
- Channel binding control: --channel-binding {none, tls-server-end-point, tls-unique}
- Separate --dc-ip for KDC/DC IP needs (esp. Kerberos) while still connecting via FQDN for LDAPS
- Optional search base DN: --base (defaults to DC=... from target domain)
- Page size knob: --page-size (best-effort; falls back if unsupported)
- Streaming exports:
    --export-json  (writes a proper JSON array, streamed via temp .jsonl)
    --export-xlsx  (constant memory mode)
    --export-csv
    --export-sqlite (chunked executemany)
- Logging, type hints, dataclass, and PEP 8 friendly structure
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import re
import sqlite3
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import AsyncIterator, Dict, List, Optional, Tuple
from urllib.parse import quote

import xlsxwriter
from msldap.commons.factory import LDAPConnectionFactory

# ----------------------------- Constants -------------------------------------

VERSION = "2.2"
DEFAULT_SCHEME = "ldaps"
DEFAULT_CBT = "tls-server-end-point"
DEFAULT_PAGE_SIZE = 1000
ROW_CHUNK = 500  # batch size for sqlite inserts

TARGET_RE = re.compile(
    r"^(?P<domain>[^/]+)/(?P<username>[^:@]+)(?::(?P<pw>[^@]*))?(?:@(?P<host>[^/]+))?$",
    re.IGNORECASE,
)
CN_TIME_GUID_RE = re.compile(
    r"^(CN=)(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}-\d{2}:\d{2})({[0-9A-F\-]+}),",
    re.IGNORECASE,
)

# ----------------------------- Data types ------------------------------------


@dataclass
class ResultRow:
    distinguished_name: str
    domain: Optional[str]
    organizational_units: Optional[str]
    created_at: Optional[str]
    volume_guid: Optional[str]
    computer_fqdn: Optional[str]
    recovery_key: Optional[str]


# ----------------------------- Utilities -------------------------------------


def split_dn_respecting_escapes(dn: str) -> List[str]:
    """
    Splits a DN at commas not escaped by backslash.
    Handles typical AD DNs.
    """
    parts: List[str] = []
    buf: List[str] = []
    esc = False
    for ch in dn:
        if esc:
            buf.append(ch)
            esc = False
            continue
        if ch == "\\":
            buf.append(ch)
            esc = True
            continue
        if ch == ",":
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return parts


def domain_to_base_dn(domain: str) -> Optional[str]:
    if not domain:
        return None
    return ",".join(f"DC={p}" for p in domain.split("."))


def parse_target(target: str) -> Tuple[str, str, Optional[str], Optional[str]]:
    m = TARGET_RE.match(target or "")
    if not m:
        raise ValueError(
            "Invalid target. Use: domain.tld/username[:password]@OptionalDCFQDN"
        )
    return m.group("domain"), m.group("username"), m.group("pw"), m.group("host")


def parse_lm_nt_hashes(hashes: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not hashes:
        return None, None
    if ":" in hashes:
        lm, nt = hashes.split(":", 1)
        return lm or None, nt or None
    # Accept bare NT hash
    return None, hashes


def first_value(v):
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def get_domain_from_dn(dn: str) -> Optional[str]:
    dcs = [
        p.split("=", 1)[1]
        for p in split_dn_respecting_escapes(dn)
        if p.lower().startswith("dc=")
    ]
    return ".".join(dcs) if dcs else None


def get_ou_path_from_dn(dn: str) -> Optional[str]:
    ous = [
        p.split("=", 1)[1]
        for p in split_dn_respecting_escapes(dn)
        if p.lower().startswith("ou=")
    ]
    return " --> ".join(ous) if ous else None


def parse_fve_entry(dn: str, attrs: Dict[str, object]) -> ResultRow:
    created_at, guid = None, None
    m = CN_TIME_GUID_RE.match(dn)
    if m:
        _, created_at, guid = m.groups()
        guid = guid.strip("{}").lower()

    parts = split_dn_respecting_escapes(dn)
    computer = None
    if len(parts) > 1 and parts[1].upper().startswith("CN="):
        computer = parts[1].split("=", 1)[1]

    recovery = (
        first_value(attrs.get("msFVE-RecoveryPassword"))
        or first_value(attrs.get("msfve-recoverypassword"))
    )
    volguid = (
        first_value(attrs.get("msFVE-VolumeGuid"))
        or first_value(attrs.get("msfve-volumeguid"))
        or guid
    )
    volguid = volguid.strip("{}").lower() if volguid else None

    return ResultRow(
        distinguished_name=dn,
        domain=get_domain_from_dn(dn),
        organizational_units=get_ou_path_from_dn(dn),
        created_at=created_at,
        volume_guid=volguid,
        computer_fqdn=computer,
        recovery_key=recovery,
    )


def build_msldap_url(
    *,
    scheme: str,
    domain: str,
    username: str,
    password_in_target: Optional[str],
    host: Optional[str],
    use_kerberos: bool,
    hashes: Optional[str],
    aes_key: Optional[str],
    no_pass: bool,
    dc_ip: Optional[str],
    channel_binding: str,
    base_dn: Optional[str],
) -> str:
    """
    Constructs an msldap URL honoring the requested auth & connection options.
    """
    _, nt = parse_lm_nt_hashes(hashes)
    auth: str
    secret: Optional[str] = None

    if use_kerberos:
        if aes_key:
            auth, secret = "kerberos-aes", aes_key
        elif nt:
            auth, secret = "kerberos-rc4", nt
        elif password_in_target is not None:
            auth, secret = "kerberos-password", password_in_target
        else:
            auth, secret = "kerberos-ccache", None
        if not dc_ip:
            raise ValueError("Kerberos selected (-k) but --dc-ip is missing.")
    else:
        if nt:
            auth, secret = "ntlm-nt", nt
        else:
            if password_in_target is None and not no_pass:
                raise ValueError(
                    "Provide a password in the target, or use --no-pass, or use --hashes/--aes-key."
                )
            auth, secret = "ntlm-password", (password_in_target or "")

    if channel_binding != "none" and scheme != "ldaps":
        logging.warning("Channel binding requires TLS. Forcing scheme=ldaps.")
        scheme = "ldaps"

    the_host = host
    if scheme == "ldaps" and not the_host:
        raise ValueError("LDAPS selected but no @FQDN specified in target.")
    if not the_host and dc_ip:
        the_host = dc_ip
    if not the_host:
        raise ValueError("No host in target and no --dc-ip provided.")

    userinfo = f"{domain}\\{username}"
    if secret is not None and auth != "kerberos-ccache":
        # URL-encode secrets to survive special characters
        userinfo += f":{quote(secret, safe='')}"

    # Include base DN as path if provided (reduces server-side scope)
    path = f"/{base_dn.strip('/')}/" if base_dn else "/"

    url = f"{scheme}+{auth}://{userinfo}@{the_host}{path}"

    params = []
    if use_kerberos and dc_ip:
        params.append(f"dc={dc_ip}")
    if channel_binding != "none":
        # carried forward for compatibility; LDAPS performs CBT automatically
        params.append(f"cbind={channel_binding}")

    if params:
        url += "?" + "&".join(params)
    return url


# ----------------------------- Exports ---------------------------------------


class ExportSinks:
    """Streaming export helpers (open once, write as we go)."""

    def __init__(
        self,
        json_path: Optional[Path],
        xlsx_path: Optional[Path],
        sqlite_path: Optional[Path],
        csv_path: Optional[Path],
    ):
        self.json_path = json_path
        self.xlsx_path = xlsx_path
        self.sqlite_path = sqlite_path
        self.csv_path = csv_path

        self._jsonl_tmp_path: Optional[Path] = None
        self._jsonl_tmp = None

        self._xlsx_wb = None
        self._xlsx_ws = None
        self._xlsx_row = 1

        self._sqlite_conn = None
        self._sqlite_cur = None
        self._sqlite_buffer: List[Tuple] = []

        self._csv = None
        self._csv_writer = None

    def open(self):
        # JSON via JSONL behind the scenes
        if self.json_path:
            self.json_path.parent.mkdir(parents=True, exist_ok=True)
            self._jsonl_tmp_path = self.json_path.with_suffix(
                self.json_path.suffix + ".tmp.jsonl"
            )
            self._jsonl_tmp = self._jsonl_tmp_path.open("w", encoding="utf-8")

        # XLSX streaming
        if self.xlsx_path:
            self.xlsx_path.parent.mkdir(parents=True, exist_ok=True)
            self._xlsx_wb = xlsxwriter.Workbook(
                str(self.xlsx_path), {"constant_memory": True}
            )
            self._xlsx_ws = self._xlsx_wb.add_worksheet()
            bold = self._xlsx_wb.add_format({"bold": True})
            headers = [
                "Computer FQDN",
                "Domain",
                "Recovery Key",
                "Volume GUID",
                "Created At",
                "Organizational Units",
                "Distinguished Name",
            ]
            self._xlsx_ws.set_row(0, 20, bold)
            for i, h in enumerate(headers):
                self._xlsx_ws.write(0, i, h)

        # SQLite (chunked)
        if self.sqlite_path:
            self.sqlite_path.parent.mkdir(parents=True, exist_ok=True)
            self._sqlite_conn = sqlite3.connect(str(self.sqlite_path))
            self._sqlite_cur = self._sqlite_conn.cursor()
            self._sqlite_cur.execute(
                """CREATE TABLE IF NOT EXISTS bitlocker_keys(
                    fqdn TEXT, domain TEXT, recoveryKey TEXT, volumeGuid TEXT,
                    createdAt TEXT, organizationalUnits TEXT, distinguishedName TEXT
                );"""
            )

        # CSV streaming
        if self.csv_path:
            self.csv_path.parent.mkdir(parents=True, exist_ok=True)
            self._csv = self.csv_path.open("w", encoding="utf-8", newline="")
            self._csv_writer = csv.writer(self._csv)
            self._csv_writer.writerow(
                [
                    "Computer FQDN",
                    "Domain",
                    "Recovery Key",
                    "Volume GUID",
                    "Created At",
                    "Organizational Units",
                    "Distinguished Name",
                ]
            )

    def write_row(self, row: ResultRow):
        # JSONL line
        if self._jsonl_tmp:
            self._jsonl_tmp.write(json.dumps(asdict(row), ensure_ascii=False) + "\n")

        # XLSX row
        if self._xlsx_ws:
            values = [
                row.computer_fqdn,
                row.domain,
                row.recovery_key,
                row.volume_guid,
                row.created_at,
                row.organizational_units,
                row.distinguished_name,
            ]
            for c, v in enumerate(values):
                self._xlsx_ws.write(self._xlsx_row, c, v)
            self._xlsx_row += 1

        # SQLite batch
        if self._sqlite_cur is not None:
            self._sqlite_buffer.append(
                (
                    row.computer_fqdn,
                    row.domain,
                    row.recovery_key,
                    row.volume_guid,
                    row.created_at,
                    row.organizational_units,
                    row.distinguished_name,
                )
            )
            if len(self._sqlite_buffer) >= ROW_CHUNK:
                self._sqlite_cur.executemany(
                    "INSERT INTO bitlocker_keys VALUES (?,?,?,?,?,?,?)",
                    self._sqlite_buffer,
                )
                self._sqlite_conn.commit()
                self._sqlite_buffer.clear()

        # CSV row
        if self._csv_writer:
            self._csv_writer.writerow(
                [
                    row.computer_fqdn,
                    row.domain,
                    row.recovery_key,
                    row.volume_guid,
                    row.created_at,
                    row.organizational_units,
                    row.distinguished_name,
                ]
            )

    def _finalize_json(self):
        """Convert the temp .jsonl to a proper JSON array at self.json_path."""
        if not (self.json_path and self._jsonl_tmp_path and self._jsonl_tmp_path.exists()):
            return

        # Close the temp writer first
        if self._jsonl_tmp and not self._jsonl_tmp.closed:
            self._jsonl_tmp.close()

        # Stream conversion: .jsonl -> .json (array)
        with self._jsonl_tmp_path.open("r", encoding="utf-8") as src, \
             self.json_path.open("w", encoding="utf-8") as dst:
            dst.write("[\n")
            first = True
            for line in src:
                line = line.strip()
                if not line:
                    continue
                if not first:
                    dst.write(",\n")
                dst.write(line)
                first = False
            dst.write("\n]\n")

        # Remove temp
        try:
            self._jsonl_tmp_path.unlink(missing_ok=True)
        except Exception:
            pass

    def close(self):
        # Flush remaining SQLite batch
        if self._sqlite_buffer and self._sqlite_cur:
            self._sqlite_cur.executemany(
                "INSERT INTO bitlocker_keys VALUES (?,?,?,?,?,?,?)",
                self._sqlite_buffer,
            )
            self._sqlite_conn.commit()
            self._sqlite_buffer.clear()

        # Close XLSX/CSV
        if self._xlsx_wb:
            self._xlsx_wb.close()
        if self._csv:
            self._csv.close()

        # Finalize JSON (convert temp .jsonl -> .json array)
        self._finalize_json()

        # Close SQLite
        if self._sqlite_conn:
            self._sqlite_conn.close()


# ----------------------------- LDAP bits -------------------------------------


async def paged_search(url: str, page_size: int) -> AsyncIterator[ResultRow]:
    factory = LDAPConnectionFactory.from_url(url)
    client = factory.get_client()

    _, err = await client.connect()
    if err:
        raise err

    ldap_filter = "(objectClass=msFVE-RecoveryInformation)"
    attrs = ["distinguishedName", "msFVE-RecoveryPassword", "msFVE-VolumeGuid"]

    try:
        # Try with explicit page_size, fall back if msldap version doesn't support the kwarg
        try:
            async for entry, e in client.pagedsearch(
                query=ldap_filter, attributes=attrs, page_size=page_size
            ):
                if e:
                    raise e
                dn = entry.get("dn") or entry.get("distinguishedName")
                attrs_map = entry.get("attributes") or entry
                if not dn:
                    continue
                yield parse_fve_entry(dn, attrs_map)
        except TypeError:
            async for entry, e in client.pagedsearch(query=ldap_filter, attributes=attrs):
                if e:
                    raise e
                dn = entry.get("dn") or entry.get("distinguishedName")
                attrs_map = entry.get("attributes") or entry
                if not dn:
                    continue
                yield parse_fve_entry(dn, attrs_map)
    finally:
        await client.disconnect()


# ----------------------------- CLI & main ------------------------------------


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Extract BitLocker recovery keys (msldap 0.5.15)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument(
        "target",
        help="Impacket-style target: domain.tld/username[:password]@OptionalDCFQDN",
    )

    g_conn = p.add_argument_group("Connection")
    g_conn.add_argument("--scheme", choices=["ldap", "ldaps"], default=DEFAULT_SCHEME)
    g_conn.add_argument(
        "--channel-binding",
        choices=["none", "tls-server-end-point", "tls-unique"],
        default=DEFAULT_CBT,
        help="Channel binding policy (LDAPS performs CBT automatically).",
    )
    g_conn.add_argument(
        "--dc-ip",
        dest="dc_ip",
        help="DC/KDC IP (required for Kerberos; useful when DNS fails).",
    )
    g_conn.add_argument(
        "--base",
        dest="base_dn",
        help="Search base DN (e.g., 'OU=Prod,DC=corp,DC=local'). "
             "Defaults to DC=... derived from the target domain.",
    )
    g_conn.add_argument(
        "--page-size",
        type=int,
        default=DEFAULT_PAGE_SIZE,
        help="LDAP paging size (best-effort; ignored if not supported).",
    )

    g_auth = p.add_argument_group("Authentication")
    g_auth.add_argument(
        "-k", "--kerberos", action="store_true",
        help="Use Kerberos. If no secret provided, use ccache."
    )
    g_auth.add_argument("--no-pass", action="store_true", help="Empty password for NTLM; with -k, prefer ccache.")
    g_auth.add_argument("--hashes", metavar="LM:NT",
                        help="LM:NT. With -k, NT used as RC4 key; else NTLM PtH.")
    g_auth.add_argument("--aes-key", dest="aes_key",
                        help="AES key for Kerberos (128/256-bit hex).")

    g_out = p.add_argument_group("Output")
    g_out.add_argument("--export-json", type=Path, help="Write results to JSON (array).")
    g_out.add_argument("--export-xlsx", type=Path, help="Write results to XLSX (streaming).")
    g_out.add_argument("--export-sqlite", type=Path, help="Write results to SQLite (chunked).")
    g_out.add_argument("--export-csv", type=Path, help="Write results to CSV (streaming).")

    p.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Logging verbosity.",
    )
    p.add_argument("-q", "--quiet", action="store_true", help="Suppress row prints.")

    return p


def validate_args(args, password_in_target: Optional[str]) -> None:
    if not args.kerberos and args.aes_key:
        raise ValueError("--aes-key requires -k/--kerberos.")
    if args.scheme == "ldaps" and args.channel_binding == "none":
        logging.warning("LDAPS without channel binding is discouraged.")
    if args.kerberos and not args.dc_ip:
        raise ValueError("Kerberos (-k) requires --dc-ip.")
    if not args.base_dn:
        # derive from target domain
        args.base_dn = domain_to_base_dn(args.domain)


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level),
        format="%(levelname)s: %(message)s",
    )


def main() -> int:
    parser = build_arg_parser()
    args = parser.parse_args()

    configure_logging(args.log_level)

    try:
        domain, user, pw, host = parse_target(args.target)
    except Exception as e:
        logging.error("Target parse error: %s", e)
        return 2

    args.domain = domain  # for validate_args()
    try:
        validate_args(args, pw)
    except Exception as e:
        logging.error("%s", e)
        return 2

    try:
        url = build_msldap_url(
            scheme=args.scheme,
            domain=domain,
            username=user,
            password_in_target=pw,
            host=host,
            use_kerberos=args.kerberos,
            hashes=args.hashes,
            aes_key=args.aes_key,
            no_pass=args.no_pass,
            dc_ip=args.dc_ip,
            channel_binding=args.channel_binding,
            base_dn=args.base_dn,
        )
        logging.debug("msldap URL: %s", url)
    except Exception as e:
        logging.error("URL build error: %s", e)
        return 2

    sinks = ExportSinks(
        json_path=args.export_json,
        xlsx_path=args.export_xlsx,
        sqlite_path=args.export_sqlite,
        csv_path=args.export_csv,
    )
    sinks.open()

    printed = 0
    total = 0
    try:
        async def runner():
            nonlocal printed, total
            async for row in paged_search(url, args.page_size):
                total += 1
                sinks.write_row(row)
                if not args.quiet and row.recovery_key:
                    print("| {:<30} | {:<30} | {} |".format(
                        (row.domain or "")[:30],
                        (row.computer_fqdn or "")[:30],
                        row.recovery_key,
                    ))
                    printed += 1

        asyncio.run(runner())
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sinks.close()
        return 130
    except Exception as e:
        logging.error("LDAP search failed: %s", e)
        sinks.close()
        return 1

    sinks.close()

    logging.info("Processed %d objects. Printed %d rows.", total, printed)
    if total == 0:
        logging.warning("No objects found for (objectClass=msFVE-RecoveryInformation).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
