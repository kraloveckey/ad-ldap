# bitlocker-keys-dumper

## Description

A system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.

## Usage

```shell
$ ./bitlocker-keys-dumper.py --help
usage: bitlocker-keys-dumper.py [-h] [--scheme {ldap,ldaps}] [--channel-binding {none,tls-server-end-point,tls-unique}] [--dc-ip DC_IP] [--base BASE_DN] [--page-size PAGE_SIZE] [-k] [--no-pass]
                                [--hashes LM:NT] [--aes-key AES_KEY] [--export-json EXPORT_JSON] [--export-xlsx EXPORT_XLSX] [--export-sqlite EXPORT_SQLITE] [--export-csv EXPORT_CSV]
                                [--log-level {DEBUG,INFO,WARNING,ERROR}] [-q]
                                target

Extract BitLocker recovery keys (msldap 0.5.15)

positional arguments:
  target                Impacket-style target: domain.tld/username[:password]@OptionalDCFQDN

options:
  -h, --help            show this help message and exit
  --log-level {DEBUG,INFO,WARNING,ERROR}
                        Logging verbosity. (default: INFO)
  -q, --quiet           Suppress row prints. (default: False)

Connection:
  --scheme {ldap,ldaps}
  --channel-binding {none,tls-server-end-point,tls-unique}
                        Channel binding policy (LDAPS performs CBT automatically). (default: tls-server-end-point)
  --dc-ip DC_IP         DC/KDC IP (required for Kerberos; useful when DNS fails). (default: None)
  --base BASE_DN        Search base DN (e.g., 'OU=Prod,DC=corp,DC=local'). Defaults to DC=... derived from the target domain. (default: None)
  --page-size PAGE_SIZE
                        LDAP paging size (best-effort; ignored if not supported). (default: 1000)

Authentication:
  -k, --kerberos        Use Kerberos. If no secret provided, use ccache. (default: False)
  --no-pass             Empty password for NTLM; with -k, prefer ccache. (default: False)
  --hashes LM:NT        LM:NT. With -k, NT used as RC4 key; else NTLM PtH. (default: None)
  --aes-key AES_KEY     AES key for Kerberos (128/256-bit hex). (default: None)

Output:
  --export-json EXPORT_JSON
                        Write results to JSON (array). (default: None)
  --export-xlsx EXPORT_XLSX
                        Write results to XLSX (streaming). (default: None)
  --export-sqlite EXPORT_SQLITE
                        Write results to SQLite (chunked). (default: None)
  --export-csv EXPORT_CSV
                        Write results to CSV (streaming). (default: None)

# or

$ ./bitlocker-keys-dumper.ps1 -Help

Required arguments:
  -dcip             : LDAP host to target, most likely the domain controller.

Optional arguments:
  -Help             : Displays this help message
  -Quiet            : Do not print keys, only export them.
  -UseCredentials   : Flag for asking for credentials to authentication
  -Credentials      : Providing PSCredentialObject for authentication
  -PageSize         : Sets the LDAP page size to use in queries (default: 5000).
  -LDAPS            : Use LDAPS instead of LDAP.
  -LogFile          : Log file to save output to.
  -ExportToCSV      : Export Bitlocker Keys in a CSV file.
  -ExportToJSON     : Export Bitlocker Keys in a JSON file.
```

To extract Bitlocker recovery keys from all the computers of the domain `domain.local` you can use this command:

```shell
./bitlocker-keys-dumper.py -d 'domain.local' -u 'Administrator' -p 'Podalirius123!' --dc-ip 192.168.1.1

# or

.\bitlocker-keys-dumper.ps1 -dcip 192.168.1.1 -ExportToCSV ./bit-keys.csv -ExportToJSON ./bit-keys.json
```