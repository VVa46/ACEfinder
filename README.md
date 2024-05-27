# ACE Finder

## Overview
ACEfinder is a Python script designed to find and analyze Access Control Entries (ACEs) within LDAP (Lightweight Directory Access Protocol). The script helps to identify and interpret ACEs, providing insights into permissions and access control settings.

## Features
- Connect to an LDAP server and search for specific ACEs.
- Parse and display details of ACEs within security descriptors.
- Options to filter and format output.

## Requirements
- Python 3.x
- `ldap3` library

You can install the required library using pip:
```sh
pip install ldap3
```

## Usage

1. Clone the repository:

```sh
Copy code
git clone https://github.com/yourusername/ace-finder.git
cd ace-finder
```

2. Ensure you have the necessary permissions to access the LDAP server and read ACEs.

3. Run the script 
```sh
python3 ACEfinder.py DCIP -u $USERNAME -p $PASSWORD
```

## Example output
The script will output details like:

```
python3 ACEfinder.py 192.168.1.200 -U admin -P 'Passw0rd!' 
                                                                                            
    @@@@@@    @@@@@@@  @@@@@@@@     @@@@@@@@  @@@  @@@  @@@  @@@@@@@   @@@@@@@@  @@@@@@@   
    @@@@@@@@  @@@@@@@@  @@@@@@@@     @@@@@@@@  @@@  @@@@ @@@  @@@@@@@@  @@@@@@@@  @@@@@@@@  
    @@!  @@@  !@@       @@!          @@!       @@!  @@!@!@@@  @@!  @@@  @@!       @@!  @@@  
    !@!  @!@  !@!       !@!          !@!       !@!  !@!!@!@!  !@!  @!@  !@!       !@!  @!@  
    @!@!@!@!  !@!       @!!!:!       @!!!:!    !!@  @!@ !!@!  @!@  !@!  @!!!:!    @!@!!@!   
    !!!@!!!!  !!!       !!!!!:       !!!!!:    !!!  !@!  !!!  !@!  !!!  !!!!!:    !!@!@!    
    !!:  !!!  :!!       !!:          !!:       !!:  !!:  !!!  !!:  !!!  !!:       !!: :!!   
    :!:  !:!  :!:       :!:          :!:       :!:  :!:  !:!  :!:  !:!  :!:       :!:  !:!  
    ::   :::   ::: :::   :: ::::      ::        ::   ::   ::   :::: ::   :: ::::  ::   :::  
    :   : :   :: :: :  : :: ::       :        :    ::    :   :: :  :   : :: ::    :   : :  
                                                                                            
    
[+] Connection successful.
[+] Logged in as RUSCO\admin
[+] Searching for users...
[-] Found 11 users in 0.00 seconds.
[+] Searching for groups...
[-] Found 44 groups in 0.00 seconds.

[!] Found anomalous permissions for User poterisuschiavo:
[+] ON USER schiavo: ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_WRITE_PROP, READ_CONTROL

[!] Found anomalous permissions for Group permessisuschiavo:
[+] ON USER schiavo: ADS_RIGHT_DS_CREATE_CHILD, ADS_RIGHT_DS_DELETE_CHILD, ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_SELF, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_WRITE_PROP, ADS_RIGHT_DS_DELETE_TREE, ADS_RIGHT_DS_LIST_OBJECT, ADS_RIGHT_DS_CONTROL_ACCESS, DELETE, READ_CONTROL, WRITE_DAC, WRITE_OWNER
[+] ON USER schiavo: ADS_RIGHT_ACTRL_DS_LIST, ADS_RIGHT_DS_READ_PROP, ADS_RIGHT_DS_WRITE_PROP, READ_CONTROL
```
## TO DO
- ADD MSOL to known privileged users

Ref:
https://learn.microsoft.com/en-us/windows/win32/ad/reading-an-objectampaposs-security-descriptor
https://learn.microsoft.com/en-us/windows/win32/secauthz/generic-access-rights
https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-entries
https://ldap3.readthedocs.io/en/latest/welcome.html