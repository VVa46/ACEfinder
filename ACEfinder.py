from ldap3 import Server, Connection, ALL, ALL_ATTRIBUTES, BASE
import struct
import time
import argparse


def print_banner():
    banner = """
                                                                                            
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
                                                                                            
    """
    if not args.nobanner:
        print(banner)
    else:
        return


COLORS = {
    'blue': 94,
    'green': 92,
    'yellow': 93,
    'red': 91
}

def color_print(text, color):
    """Print text in the specified color."""
    try:
        code = COLORS[color]
    except KeyError:
        raise KeyError(f'Invalid text color: {color}')
    
    print(f'\033[{code}m{text}\033[0m')

def verbose_output(verbo):
    if args.verbose == True:
        print(verbo)

SID_map = {}

def search_root_dse(dc_ip, dc_port=389):
    try:
        server = Server(dc_ip, port=dc_port)
        connection = Connection(server)
        
        # Bind to LDAP server anonymously
        connection.bind()
        
        # Search the root DSE with an empty search filter
        connection.search(search_base="", search_filter="(objectClass=*)", search_scope=BASE, attributes=["*"])
        
        if connection.entries:
            # Print information from the root DSE
            for entry in connection.entries:
                domain = entry["rootDomainNamingContext"].value
                return domain
        else:
            print("[-] No entries found in root DSE.")
            exit(1)
    except Exception as e:
        print("Error:", e)
    finally:
        connection.unbind()


def establish_connection(dc_ip, username, password, dc_port):
    try:
        # Set up LDAP connection
        server = Server(dc_ip, port=dc_port, get_info=ALL)
        connection = Connection(server, user=username, password=password, auto_bind=True)
        
        # Check if the connection is successful and print the user connected
        if connection.bound:
            color_print("[+] Connection successful.",'green')
            user_con = connection.extend.standard.who_am_i()
            color_print("[+] Logged in as " + user_con.removeprefix("u:"),'green')
            return connection
        else:
            print("Failed to bind to LDAP server.")
            return None
    except Exception as e:
        print("Error:", e)
        quit()


def close_connection(connection):
    # Close the connection
    try:
        connection.unbind()
    except Exception as e:
        print("Error while closing connection:", e)

# print to file the output
def save_to_file(print_me):
    if args.output_file:
        with open(f'{args.output_file}', 'a') as f:
            # Append to the specified file
            f.write(print_me + "\n")


# Function to parse and display security descriptor
def parse_security_descriptor(sd, target_dn, connection, user_sid=None):
    if sd is None:
        return "No security descriptor available"

    try:
        # Unpack security descriptor header
        control = struct.unpack('<H', sd[2:4])[0]
        owner_offset = struct.unpack('<L', sd[4:8])[0]
        group_offset = struct.unpack('<L', sd[8:12])[0]
        sacl_offset = struct.unpack('<L', sd[12:16])[0]
        dacl_offset = struct.unpack('<L', sd[16:20])[0]

        sd_info = []
        sd_info.append(f"Control Flags: {hex(control)}")
        sd_info.append(f"Owner SID Offset: {owner_offset} (offset within the security descriptor)")
        sd_info.append(f"Group SID Offset: {group_offset} (offset within the security descriptor)")
        sd_info.append(f"SACL Offset: {sacl_offset} (offset within the security descriptor)")
        sd_info.append(f"DACL Offset: {dacl_offset} (offset within the security descriptor)")

        permissions_info = []

        if dacl_offset > 0:
            sd_info.append("Discretionary ACL (DACL):")
            dacl = sd[dacl_offset:]
            ace_count = struct.unpack('<H', dacl[4:6])[0]
            ace_start = 8
            for i in range(ace_count):
                ace_type = dacl[ace_start]
                ace_flags = dacl[ace_start + 1]
                ace_size = struct.unpack('<H', dacl[ace_start + 2:ace_start + 4])[0]
                ace_mask = struct.unpack('<L', dacl[ace_start + 4:ace_start + 8])[0]
                ace_sid = dacl[ace_start + 8:ace_start + ace_size]

                sid_str = parse_sid(ace_sid)
                permissions = parse_ace_mask(ace_mask)

                dn_of_sid = ""
                sd_info.append(f" ACE {i + 1}:")
                sd_info.append(f"  - ACE Type: {ace_type}")
                sd_info.append(f"  - ACE Flags: {hex(ace_flags)}")
                sd_info.append(f"  - ACE Mask: {hex(ace_mask)}")
                sd_info.append(f"  - ACE SID: {sid_str} (resolved to {dn_of_sid})")
                sd_info.append(f"  - Permissions: {permissions}")
                sd_info.append(f"  - Applied to: {target_dn}")

                if user_sid and sid_str == user_sid:
                    applied_to_cn = extract_cn(str(target_dn))
                    applied_to_type = get_entity_type(connection, target_dn) #Controllare se crea overhead
                    #dn_of_sid_cn = extract_cn(str(dn_of_sid))
                    #permissions_info.append(f"User {dn_of_sid_cn} has permissions on {applied_to_type} {applied_to_cn}: {permissions}")
                    if len(permissions) > 0:
                        permissions_info.append(f"[+] ON {applied_to_type} {applied_to_cn}: {permissions}")

                ace_start += ace_size

        return "\n".join(sd_info), permissions_info
    except Exception as e:
        print(f"Error parsing security descriptor: {e}")
        return "", []

# Function to convert binary SID to string SID
def parse_sid(sid):
    try:
        if len(sid) < 8:
            raise ValueError("SID too short")

        revision = sid[0]
        sub_authority_count = sid[1]
        if len(sid) < 8 + 4 * sub_authority_count:
            raise ValueError("SID buffer too short for sub-authorities")

        identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
        sub_authorities = [struct.unpack('<L', sid[8 + 4 * i:12 + 4 * i])[0] for i in range(sub_authority_count)]

        sid_str = f"S-{revision}-{identifier_authority}-" + '-'.join(map(str, sub_authorities))
        return sid_str
    except Exception as e:
        print(f"Error parsing SID: {e}")
        return None

# Function to parse ACE Mask to human-readable permissions
def parse_ace_mask(ace_mask):
    permissions = {
        0x00000001: "ADS_RIGHT_DS_CREATE_CHILD",
        0x00000002: "ADS_RIGHT_DS_DELETE_CHILD",
        0x00000004: "ADS_RIGHT_ACTRL_DS_LIST",
        0x00000008: "ADS_RIGHT_DS_SELF",
        0x00000010: "ADS_RIGHT_DS_READ_PROP",
        0x00000020: "ADS_RIGHT_DS_WRITE_PROP",
        0x00000040: "ADS_RIGHT_DS_DELETE_TREE",
        0x00000080: "ADS_RIGHT_DS_LIST_OBJECT",
        0x00000100: "ADS_RIGHT_DS_CONTROL_ACCESS",
        0x00010000: "DELETE",
        0x00020000: "READ_CONTROL",
        0x00040000: "WRITE_DAC",
        0x00080000: "WRITE_OWNER",
        0x00100000: "SYNCHRONIZE",
        0x01000000: "ACCESS_SYSTEM_SECURITY",
        0x02000000: "MAX_ALLOWED",
        0x08000000: "GENERIC_ALL",
        0x10000000: "GENERIC_EXECUTE",
        0x20000000: "GENERIC_WRITE",
        0x40000000: "GENERIC_READ",
    }
    result = [name for bit, name in permissions.items() if ace_mask & bit]
    return ", ".join(result)

# Function to resolve SID to DN
def sid_to_dn(connection, sid_str):
    if sid_str is None or not sid_str.startswith("S-"):
        return "Invalid SID"
    try:
        if sid_str in SID_map:
            return SID_map[sid_str]
        sid_str_ldap = sid_str.replace("-", "\\-")
        connection.search(f'{domain}', f'(objectSid={sid_str_ldap})', attributes=['distinguishedName'])
        if connection.entries:
            dn = connection.entries[0]['distinguishedName'].value
            SID_map[sid_str] = dn
            return dn
        else:
            pass
    except Exception as e:
        print(f"Error resolving SID: {e}")
    return "Unknown"

# Function to extract CN from DN
def extract_cn(dn):
    for part in dn.split(','):
        if part.startswith('CN='):
            return part[3:]
    return dn

# Function to get the entity type (User or Group)
def get_entity_type(connection, dn):
    connection.search(f'{domain}', f'(distinguishedName={dn})', attributes=['objectClass'])
    if connection.entries:
        object_classes = connection.entries[0]['objectClass'].values
        return "USER" if "user" in object_classes else "GROUP"
    return "UNKNOWN"

# Function to get the object class for a user or group DN
def get_object_class(connection, dn):
    connection.search(f'{domain}', f'(distinguishedName={dn})', attributes=['objectClass'])
    if connection.entries:
        object_classes = connection.entries[0]['objectClass'].values
        return object_classes
    return []

permissions_summary = []

# def parse_user(entry,entry_type,connection, user_sid):
#     dn = str(entry['distinguishedName'])
#     security_descriptor = entry['nTSecurityDescriptor'].raw_values[0]
#     human_readable_sd, permissions_info = parse_security_descriptor(security_descriptor, dn, connection, user_sid)
#     if permissions_info:
#         verbose_output(f"{entry_type} DN: {dn}")
#         verbose_output("Security Descriptor:")
#         verbose_output(human_readable_sd)
#         verbose_output("-" * 40)
#         permissions_summary.extend(permissions_info)


# Function to process entries (users and groups)
def process_entries(connection, search_filter, entry_type, user_sid=None):
    permissions_summary = []
    #verbose_output(f"Searching with filter: {search_filter}")
    connection.search(f'{domain}', search_filter, attributes=['distinguishedName', 'nTSecurityDescriptor'])
    if not connection.entries:
        print("No entries found.")
        return permissions_summary

    for entry in connection.entries:
        dn = str(entry['distinguishedName'])
        security_descriptor = entry['nTSecurityDescriptor'].raw_values[0]
        human_readable_sd, permissions_info = parse_security_descriptor(security_descriptor, dn, connection, user_sid)
        if permissions_info:
            verbose_output((f"{entry_type} DN: {dn}"))
            verbose_output("Security Descriptor:")
            verbose_output(human_readable_sd)
            verbose_output("-" * 40)
            permissions_summary.extend(permissions_info)
    return permissions_summary


# Function to get the SID for a user or group DN
def get_sid(connection, dn):
    try:
        connection.search(f'{domain}', f'(distinguishedName={dn})', attributes=['objectSid'])
        if connection.entries:
            sid = connection.entries[0]['objectSid'].value
            return sid
    except Exception as e:
        verbose_output(f"Error getting SID for {dn}: {e}")
    return None

# Main function
def main():
    
    print_banner()
    
    
    start_time = time.time()
    connection = establish_connection(dc_ip, username, password, dc_port)
    
    #excluded known users and groups with wide permissions
    excluded_user = '(&(objectClass=user)(!(memberOf=CN=Domain Admins,CN=Users,DC=example,DC=com))(!(memberOf=CN=Enterprise Admins,CN=Users,DC=example,DC=com))(!(memberOf=CN=Administrators,CN=Builtin,DC=example,DC=com)))'
    excluded_group = '(&(objectClass=group)(!(cn=Domain Admins))(!(cn=Enterprise Admins))(!(cn=Administrators))(!(cn=Account Operators))(!(cn=Pre-Windows 2000 Compatible Access))(!(cn=*Windows 2000*))(!(cn=MSOL*)))'
    
    # Process all users and groups
    print("[+] Searching for users...")
    start_search_users = time.time()
    connection.search(f'{domain}', excluded_user, attributes=['distinguishedName'])
    users = [entry['distinguishedName'].value for entry in connection.entries]
    color_print(f"[-] Found {len(users)} users in {time.time() - start_search_users:.2f} seconds.",'yellow')

    print("[+] Searching for groups...")
    start_search_groups = time.time()
    connection.search(f'{domain}', excluded_group, attributes=['distinguishedName'])
    groups = [entry['distinguishedName'].value for entry in connection.entries]
    color_print(f"[-] Found {len(groups)} groups in {time.time() - start_search_groups:.2f} seconds.",'yellow')

    all_entries = users + groups
    verbose_output(f"Processing {len(all_entries)} entries.")

    for entry_dn in all_entries:
        verbose_output(f"Processing DN: {entry_dn}")
        entry_sid = get_sid(connection, entry_dn)
        if entry_sid:
            object_classes = get_object_class(connection, entry_dn)
            entry_type = "Group" if "group" in object_classes else "User"
            user_permissions = process_entries(connection, '(objectClass=user)', entry_type, entry_sid)
            group_permissions = process_entries(connection, '(objectClass=group)', entry_type, entry_sid)

            if user_permissions or group_permissions:
                cn = extract_cn(str(entry_dn))
                verbose_output(f"\nPermissions for {entry_type} {cn}:")
                color_print(f"\n[!] Found anomalous permissions for {entry_type} {cn}:",'red')
                for permission in user_permissions:
                    color_print(permission,'blue')
                for permission in group_permissions:
                    color_print(permission,'blue')
        else:
            verbose_output(f"Could not find SID for {entry_dn}")

    connection.unbind()
    print(f"Script completed in {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(
            prog='ACEfinder', 
            description="ACE enumeration tool.",
            usage="ACEfinder.py DCIP -U username -P password",
            epilog="GG")

    parser.add_argument("DCIP", type=str, help="Domain Controller IP address.")
    parser.add_argument('-U', '--username',required=True, help="Username of the domain")
    parser.add_argument('-P', '--password', required=True, help="Password of the domain user")
    parser.add_argument('-v', '--verbose', required=False, help="Print verbose output, CAUTION IT PRINTS TONS OF OUTPUT!", action="store_true", default=False)
    parser.add_argument('-nb', '--nobanner', required=False, help="Do not print the banner", action="store_true", default=False)

    args = parser.parse_args()

    dc_ip = args.DCIP
    dc_port = 389
    username = args.username
    password = args.password
    domain = search_root_dse(dc_ip)

    main()
    
