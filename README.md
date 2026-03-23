# ad-ldap

<p align="center"><img src=".assets/ad.png" width="200px"></p>
<h5 align="center">A collection of simple and different a system administration or post-exploitation tools written on Powershell or Batch that simplify work and dumping (extracting) data from Active Directory (LDAP).</h5>

---

- [`ad-inventory.ps1`](./ad-inventory/ad-inventory.ps1) – script to inventory computers in Active Directory. After launching it polls the specified computers in [**ou.txt**](./ad-inventory/ou.txt) and sends to mail an archive with files for each OU from [**ou.txt**](./ad-inventory/ou.txt) (**OU-Computers.csv** and **OU-Software.csv** – specifying the name of the OU).
  - [`.env`](./ad-inventory/.env) – the file in which contain the password for SMTP login (for **AUTH_USER@**).
  - [`ou.txt`](./ad-inventory/ou.txt) – this file must contain the full paths of the OU with Active Directory computers. This file must be located in the same directory when starting [**ad-inventory.ps1**](./ad-inventory/ad-inventory.ps1).
  - [`ad-report.ps1`](./ad-inventory/ad-report.ps1) – script gathers statistics about user accounts (total, active, disabled, new, service accounts) and groups (those missing a description) from specific OUs. It then saves this information into a dated text file and send by email.

> [!NOTE] Description of the files that are sent to the mail in the archive after ad-inventory.ps1 execution.
>| Name      |  Description |
> | ----------- |  ----------- |
> | `OU-Computers.csv` | Contains information on computers: Name, When online, OU, OS, OS Version, IP, CPU, Frequency – MHz, Number of cores, RAM capacity – MB, Drive capacity – GB, Drive models. |
> | `OU-Software.csv` | Contains information on software, the file contains a list of all found software and check marks against computers where it is installed. |

---

- [`bitlocker-keys-dumper`](./bitlocker-keys-dumper) – a system administration or post-exploitation script to automatically extract the bitlocker recovery keys from a domain.

---

- [`gmsa-dumper`](./gmsa-dumper/gmsa-dumper.py) – lists who can read any gMSA password blobs and parses them if the current user has access.

---

- [`laps-dumper`](./laps-dumper/laps-dumper.py) – dumping LAPS passwords from Python.

---