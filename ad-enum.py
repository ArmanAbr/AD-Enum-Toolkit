#!/usr/bin/env python3
"""
Active Directory Enumeration Tool
Requirements: pip install impacket ldap3 dnspython
Usage: python3 ad-enum.py -d domain.local -u username -p password --dc-ip 192.168.1.1 --all
"""

import argparse
import sys
import csv
import json
import socket
from datetime import datetime, timedelta
from impacket.ldap import ldap, ldapasn1
from impacket.smbconnection import SMBConnection
from impacket.examples.utils import parse_target
from ldap3 import Server, Connection, ALL, NTLM, SUBTREE


class ADEnumerator:
    def __init__(self, domain, username, password, dc_ip=None, lmhash='', nthash=''):
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip or self._resolve_dc(domain)
        self.lmhash = lmhash
        self.nthash = nthash
        self.base_dn = self._get_base_dn()
        self.conn = None
        self.results = {}
        
    def _resolve_dc(self, domain):
        """Resolve domain controller IP via DNS"""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"[-] Could not resolve {domain}. Please specify --dc-ip")
            sys.exit(1)
    
    def _get_base_dn(self):
        """Convert domain to LDAP base DN"""
        return ','.join([f"DC={part}" for part in self.domain.split('.')])
    
    def connect_ldap(self):
        """Establish LDAP connection"""
        try:
            server = Server(self.dc_ip, get_info=ALL)
            user = f"{self.domain}\\{self.username}"
            
            if self.nthash:
                self.conn = Connection(server, user=user, password=self.lmhash + ':' + self.nthash, 
                                     authentication=NTLM, auto_bind=True)
            else:
                self.conn = Connection(server, user=user, password=self.password, 
                                     authentication=NTLM, auto_bind=True)
            
            print(f"[+] Connected to LDAP at {self.dc_ip}")
            return True
        except Exception as e:
            print(f"[-] LDAP connection failed: {e}")
            return False
    
    def search(self, filter_str, attributes, base=None):
        """Perform LDAP search"""
        base = base or self.base_dn
        self.conn.search(search_base=base, search_filter=filter_str, 
                        search_scope=SUBTREE, attributes=attributes)
        return self.conn.entries
    
    def enum_domain_info(self):
        """Enumerate domain and forest information"""
        print("[*] Enumerating domain information...")
        
        entries = self.search(
            '(objectClass=domain)',
            ['name', 'objectSid', 'msDS-Behavior-Version', 'fSMORoleOwner', 'namingContexts']
        )
        
        domain_info = []
        for entry in entries:
            info = {
                'name': str(entry.name) if hasattr(entry, 'name') else '',
                'sid': str(entry.objectSid) if hasattr(entry, 'objectSid') else '',
                'functional_level': str(entry['msDS-Behavior-Version']) if hasattr(entry, 'msDS-Behavior-Version') else '',
            }
            domain_info.append(info)
        
        self.results['domain_info'] = domain_info
        print(f"[+] Found domain: {domain_info[0]['name'] if domain_info else 'N/A'}")
        return domain_info
    
    def enum_users(self):
        """Enumerate users with interesting attributes"""
        print("[*] Enumerating users...")
        
        attributes = ['sAMAccountName', 'userPrincipalName', 'displayName', 'description',
                     'memberOf', 'userAccountControl', 'pwdLastSet', 'lastLogon',
                     'servicePrincipalName', 'adminCount', 'objectSid']
        
        entries = self.search('(objectClass=user)', attributes)
        
        users = []
        kerberoastable = []
        asreproastable = []
        admin_count = []
        password_never_expires = []
        
        for entry in entries:
            uac = int(entry.userAccountControl.value) if hasattr(entry, 'userAccountControl') else 0
            spn = entry.servicePrincipalName.values if hasattr(entry, 'servicePrincipalName') else []
            
            user = {
                'username': str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else '',
                'upn': str(entry.userPrincipalName) if hasattr(entry, 'userPrincipalName') else '',
                'name': str(entry.displayName) if hasattr(entry, 'displayName') else '',
                'description': str(entry.description) if hasattr(entry, 'description') else '',
                'enabled': not (uac & 0x2),  
                'pwd_last_set': str(entry.pwdLastSet) if hasattr(entry, 'pwdLastSet') else '',
                'spns': '; '.join(spn),
                'admin_count': str(entry.adminCount) if hasattr(entry, 'adminCount') else '0',
                'sid': str(entry.objectSid) if hasattr(entry, 'objectSid') else '',
            }
            users.append(user)
            
            if spn:
                kerberoastable.append(user)
            if uac & 0x400000:  
                asreproastable.append(user)
            if hasattr(entry, 'adminCount') and entry.adminCount.value == 1:
                admin_count.append(user)
            if uac & 0x10000:  
                password_never_expires.append(user)
        
        self.results['users'] = users
        self.results['kerberoastable_users'] = kerberoastable
        self.results['asrep_roastable'] = asreproastable
        self.results['admin_count_users'] = admin_count
        
        print(f"[+] Users: {len(users)} total, {len(kerberoastable)} Kerberoastable, "
              f"{len(asreproastable)} AS-REP roastable, {len(admin_count)} adminCount")
        return users
    
    def enum_groups(self):
        """Enumerate groups and memberships"""
        print("[*] Enumerating groups...")
        
        attributes = ['cn', 'sAMAccountName', 'groupType', 'description', 'member', 'objectSid']
        entries = self.search('(objectClass=group)', attributes)
        
        groups = []
        privileged_groups = ['Domain Admins', 'Enterprise Admins', 'Schema Admins',
                           'Administrators', 'Account Operators', 'Backup Operators',
                           'Print Operators', 'Server Operators']
        
        privileged = []
        
        for entry in entries:
            members = entry.member.values if hasattr(entry, 'member') else []
            group = {
                'name': str(entry.sAMAccountName) if hasattr(entry, 'sAMAccountName') else '',
                'cn': str(entry.cn) if hasattr(entry, 'cn') else '',
                'description': str(entry.description) if hasattr(entry, 'description') else '',
                'member_count': len(members),
                'members': '; '.join([str(m) for m in members[:20]]) + ('...' if len(members) > 20 else ''),
                'sid': str(entry.objectSid) if hasattr(entry, 'objectSid') else '',
            }
            groups.append(group)
            
            if group['name'] in privileged_groups:
                privileged.append(group)
        
        self.results['groups'] = groups
        self.results['privileged_groups'] = privileged
        
        print(f"[+] Groups: {len(groups)} total, {len(privileged)} privileged")
        return groups
    
    def enum_computers(self):
        """Enumerate computer accounts"""
        print("[*] Enumerating computers...")
        
        attributes = ['sAMAccountName', 'dNSHostName', 'operatingSystem', 
                     'operatingSystemVersion', 'lastLogon', 'description', 'servicePrincipalName']
        entries = self.search('(objectClass=computer)', attributes)
        
        computers = []
        servers = []
        
        for entry in entries:
            os = str(entry.operatingSystem) if hasattr(entry, 'operatingSystem') else ''
            computer = {
                'name': str(entry.sAMAccountName).rstrip('$') if hasattr(entry, 'sAMAccountName') else '',
                'dns_hostname': str(entry.dNSHostName) if hasattr(entry, 'dNSHostName') else '',
                'os': os,
                'os_version': str(entry.operatingSystemVersion) if hasattr(entry, 'operatingSystemVersion') else '',
                'description': str(entry.description) if hasattr(entry, 'description') else '',
            }
            computers.append(computer)
            
            if 'Server' in os:
                servers.append(computer)
        
        self.results['computers'] = computers
        self.results['servers'] = servers
        
        print(f"[+] Computers: {len(computers)} total, {len(servers)} servers")
        return computers
    
    def enum_trusts(self):
        """Enumerate domain trusts"""
        print("[*] Enumerating trusts...")
        
        attributes = ['cn', 'trustPartner', 'trustType', 'trustDirection', 'trustAttributes']
        entries = self.search('(objectClass=trustedDomain)', attributes)
        
        trusts = []
        for entry in entries:
            trust = {
                'name': str(entry.cn) if hasattr(entry, 'cn') else '',
                'partner': str(entry.trustPartner) if hasattr(entry, 'trustPartner') else '',
                'type': str(entry.trustType) if hasattr(entry, 'trustType') else '',
                'direction': str(entry.trustDirection) if hasattr(entry, 'trustDirection') else '',
            }
            trusts.append(trust)
        
        self.results['trusts'] = trusts
        print(f"[+] Trusts: {len(trusts)} found")
        return trusts
    
    def enum_gpos(self):
        """Enumerate Group Policy Objects"""
        print("[*] Enumerating GPOs...")
        
        attributes = ['displayName', 'gPCFileSysPath', 'versionNumber', 'name']
        entries = self.search('(objectClass=groupPolicyContainer)', attributes)
        
        gpos = []
        for entry in entries:
            gpo = {
                'display_name': str(entry.displayName) if hasattr(entry, 'displayName') else '',
                'path': str(entry.gPCFileSysPath) if hasattr(entry, 'gPCFileSysPath') else '',
                'version': str(entry.versionNumber) if hasattr(entry, 'versionNumber') else '',
            }
            gpos.append(gpo)
        
        self.results['gpos'] = gpos
        print(f"[+] GPOs: {len(gpos)} found")
        return gpos
    
    def check_smb_signing(self):
        """Check SMB signing requirements on discovered hosts"""
        print("[*] Checking SMB signing on discovered computers...")
        
        results = []
        computers = self.results.get('computers', [])
        
        for computer in computers[:20]: 
            host = computer.get('dns_hostname') or computer.get('name')
            if not host:
                continue
                
            try:
                smb = SMBConnection(host, host, sess_port=445)
                signing = smb.isSigningRequired()
                results.append({
                    'host': host,
                    'smb_signing_required': signing,
                    'os': computer.get('os', '')
                })
                smb.close()
            except Exception as e:
                results.append({
                    'host': host,
                    'smb_signing_required': 'Unknown',
                    'error': str(e)
                })
        
        self.results['smb_signing'] = results
        print(f"[+] SMB signing checked on {len(results)} hosts")
        return results
    
    def save_results(self, output_dir='ad-enum-results'):
        """Save all results to JSON and CSV"""
        import os
        os.makedirs(output_dir, exist_ok=True)
        
        json_path = os.path.join(output_dir, f'ad-enum-{datetime.now().strftime("%Y%m%d-%H%M%S")}.json')
        with open(json_path, 'w') as f:
            json.dump(self.results, f, indent=2, default=str)
        
        for key, data in self.results.items():
            if isinstance(data, list) and data:
                csv_path = os.path.join(output_dir, f'{key}.csv')
                keys = data[0].keys()
                with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    writer.writerows(data)
        
        print(f"[+] Results saved to {output_dir}/")
        print(f"[+] JSON summary: {json_path}")


def main():
    parser = argparse.ArgumentParser(description='Active Directory Enumeration Tool')
    parser.add_argument('-d', '--domain', required=True, help='Domain name')
    parser.add_argument('-u', '--username', required=True, help='Username')
    parser.add_argument('-p', '--password', required=True, help='Password')
    parser.add_argument('--dc-ip', help='Domain Controller IP')
    parser.add_argument('--nthash', help='NTLM hash for pass-the-hash')
    parser.add_argument('--all', action='store_true', help='Run all enumeration modules')
    parser.add_argument('--users', action='store_true', help='Enumerate users')
    parser.add_argument('--groups', action='store_true', help='Enumerate groups')
    parser.add_argument('--computers', action='store_true', help='Enumerate computers')
    parser.add_argument('--trusts', action='store_true', help='Enumerate trusts')
    parser.add_argument('--gpos', action='store_true', help='Enumerate GPOs')
    parser.add_argument('--smb', action='store_true', help='Check SMB signing')
    parser.add_argument('-o', '--output', default='ad-enum-results', help='Output directory')
    
    args = parser.parse_args()
    
    all_modules = args.all or not any([args.users, args.groups, args.computers, 
                                       args.trusts, args.gpos, args.smb])
    
    enumerator = ADEnumerator(
        domain=args.domain,
        username=args.username,
        password=args.password,
        dc_ip=args.dc_ip,
        nthash=args.nthash or ''
    )
    
    if not enumerator.connect_ldap():
        sys.exit(1)
    
    if all_modules or args.users:
        enumerator.enum_users()
    if all_modules or args.groups:
        enumerator.enum_groups()
    if all_modules or args.computers:
        enumerator.enum_computers()
    if all_modules or args.trusts:
        enumerator.enum_trusts()
    if all_modules or args.gpos:
        enumerator.enum_gpos()
    if all_modules or args.smb:
        enumerator.check_smb_signing()
    
    enumerator.save_results(args.output)


if __name__ == '__main__':
    main()
