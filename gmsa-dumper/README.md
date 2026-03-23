# gmsa-dumper

## Description

Lists who can read any gMSA password blobs and parses them if the current user has access.

## Usage

Basic:

```shell
python3 gmsa-dumper.py -u user -p password -d domain.local
```

Pass the Hash, specific LDAP server:

`$ python gmsa-dumper.py -u user -p 304106f739822ea2ad8ebe23f802d078:8126756fb2e69697bfcb04816e685839 -d domain.local -l dc01.domain.local`

Kerberos Authentication, specific LDAP server:

```shell
python gmsa-dumper.py -k -d domain.local -l dc01.domain.local
```