!/bin/bash
# Active Directory Enumeration Script for Linux
# Requires: ldapsearch, rpcclient, enum4linux-ng, crackmapexec (optional)
# Usage: ./ad-enum.sh -d domain.local -u user -p password --dc-ip 192.168.1.1

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' 

OUTPUT_DIR="ad-enum-$(date +%Y%m%d-%H%M%S)"
ALL=false
LDAP_PORT=389
LDAP_SSL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -d|--domain) DOMAIN="$2"; shift 2 ;;
        -u|--username) USERNAME="$2"; shift 2 ;;
        -p|--password) PASSWORD="$2"; shift 2 ;;
        --dc-ip) DC_IP="$2"; shift 2 ;;
        --ldaps) LDAP_SSL=true; LDAP_PORT=636; shift ;;
        -o|--output) OUTPUT_DIR="$2"; shift 2 ;;
        --all) ALL=true; shift ;;
        --users) ENUM_USERS=true; shift ;;
        --groups) ENUM_GROUPS=true; shift ;;
        --computers) ENUM_COMPUTERS=true; shift ;;
        --shares) ENUM_SHARES=true; shift ;;
        --policies) ENUM_POLICIES=true; shift ;;
        --help) show_help; exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

show_help() {
    echo "Active Directory Enumeration Script"
    echo "Usage: $0 -d domain.local -u user -p password --dc-ip 192.168.1.1 [options]"
    echo ""
    echo "Options:"
    echo "  --all           Run all enumeration modules"
    echo "  --users         Enumerate users"
    echo "  --groups        Enumerate groups"
    echo "  --computers     Enumerate computers"
    echo "  --shares        Enumerate SMB shares"
    echo "  --policies      Enumerate password policies"
    echo "  --ldaps         Use LDAPS (port 636)"
    echo "  -o, --output    Output directory (default: ad-enum-TIMESTAMP)"
}

if [[ -z "$DOMAIN" || -z "$USERNAME" || -z "$PASSWORD" || -z "$DC_IP" ]]; then
    echo -e "${RED}[-] Missing required arguments: --domain, --username, --password, --dc-ip${NC}"
    show_help
    exit 1
fi

if $ALL; then
    ENUM_USERS=true
    ENUM_GROUPS=true
    ENUM_COMPUTERS=true
    ENUM_SHARES=true
    ENUM_POLICIES=true
fi

mkdir -p "$OUTPUT_DIR"
echo -e "${CYAN}[*] Output directory: $OUTPUT_DIR${NC}"

BASE_DN=$(echo "$DOMAIN" | sed 's/\./,DC=/g; s/^/DC=/')

if $LDAP_SSL; then
    LDAP_SCHEME="ldaps"
else
    LDAP_SCHEME="ldap"
fi

LDAP_CONN="${LDAP_SCHEME}://${DC_IP}:${LDAP_PORT}"

run_ldapsearch() {
    local filter="$1"
    local attrs="$2"
    local output_file="$3"
    
    echo -e "${YELLOW}[*] LDAP Query: $filter${NC}"
    
    ldapsearch -x -H "$LDAP_CONN" -D "${USERNAME}@${DOMAIN}" -w "$PASSWORD" \
        -b "$BASE_DN" "$filter" $attrs \
        -o ldif-wrap=no > "$output_file" 2>&1
    
    local count=$(grep -c "^dn:" "$output_file" 2>/dev/null || echo 0)
    echo -e "${GREEN}[+] Results: $count entries -> $output_file${NC}"
}

if [[ "$ENUM_USERS" == true ]]; then
    echo -e "\n${CYAN}========== USER ENUMERATION ==========${NC}"
    
    run_ldapsearch "(objectClass=user)" \
        "sAMAccountName userPrincipalName displayName description memberOf userAccountControl pwdLastSet lastLogon servicePrincipalName adminCount" \
        "$OUTPUT_DIR/users.ldif"
    
    echo -e "${YELLOW}[*] Extracting Kerberoastable users...${NC}"
    grep -A 20 "servicePrincipalName:" "$OUTPUT_DIR/users.ldif" | grep "sAMAccountName:" | sort -u > "$OUTPUT_DIR/kerberoastable_users.txt"
    
    echo -e "${YELLOW}[*] Extracting adminCount users...${NC}"
    grep -B 5 "adminCount: 1" "$OUTPUT_DIR/users.ldif" | grep "sAMAccountName:" | sort -u > "$OUTPUT_DIR/admin_count_users.txt"
    
    echo -e "${GREEN}[+] User extraction complete${NC}"
fi

if [[ "$ENUM_GROUPS" == true ]]; then
    echo -e "\n${CYAN}========== GROUP ENUMERATION ==========${NC}"
    
    run_ldapsearch "(objectClass=group)" \
        "cn sAMAccountName groupType description member objectSid" \
        "$OUTPUT_DIR/groups.ldif"
    
    echo -e "${YELLOW}[*] Extracting privileged group members...${NC}"
    for group in "Domain Admins" "Enterprise Admins" "Schema Admins" "Administrators" "Account Operators" "Backup Operators"; do
        grep -A 100 "cn: $group" "$OUTPUT_DIR/groups.ldif" | grep "member:" | sed 's/member: //' > "$OUTPUT_DIR/group_${group// /_}_members.txt"
    done
fi

if [[ "$ENUM_COMPUTERS" == true ]]; then
    echo -e "\n${CYAN}========== COMPUTER ENUMERATION ==========${NC}"
    
    run_ldapsearch "(objectClass=computer)" \
        "sAMAccountName dNSHostName operatingSystem operatingSystemVersion lastLogon description" \
        "$OUTPUT_DIR/computers.ldif"
    
    grep -B 2 "operatingSystem:.*Server" "$OUTPUT_DIR/computers.ldif" | grep "dNSHostName:" | sed 's/dNSHostName: //' > "$OUTPUT_DIR/servers.txt"
fi

echo -e "\n${CYAN}========== TRUST ENUMERATION ==========${NC}"
run_ldapsearch "(objectClass=trustedDomain)" \
    "cn trustPartner trustType trustDirection trustAttributes" \
    "$OUTPUT_DIR/trusts.ldif"

echo -e "\n${CYAN}========== GPO ENUMERATION ==========${NC}"
run_ldapsearch "(objectClass=groupPolicyContainer)" \
    "displayName gPCFileSysPath versionNumber" \
    "$OUTPUT_DIR/gpos.ldif"

if [[ "$ENUM_POLICIES" == true ]]; then
    echo -e "\n${CYAN}========== PASSWORD POLICY ==========${NC}"
    
    echo -e "${YELLOW}[*] Trying rpcclient...${NC}"
    rpcclient -U "${DOMAIN}/${USERNAME}%${PASSWORD}" "$DC_IP" -c "querydominfo" > "$OUTPUT_DIR/domain_info_rpc.txt" 2>&1 || true
    rpcclient -U "${DOMAIN}/${USERNAME}%${PASSWORD}" "$DC_IP" -c "enumdomusers" > "$OUTPUT_DIR/users_rpc.txt" 2>&1 || true
    
    if command -v enum4linux-ng &> /dev/null; then
        echo -e "${YELLOW}[*] Running enum4linux-ng...${NC}"
        enum4linux-ng -u "$USERNAME" -p "$PASSWORD" -P "$DC_IP" -oJ "$OUTPUT_DIR/enum4linux" || true
    else
        echo -e "${YELLOW}[!] enum4linux-ng not found, skipping${NC}"
    fi
    
    run_ldapsearch "(objectClass=domainDNS)" \
        "maxPwdAge minPwdAge minPwdLength pwdHistoryLength pwdProperties lockoutThreshold lockoutDuration" \
        "$OUTPUT_DIR/password_policy.ldif"
fi

if [[ "$ENUM_SHARES" == true ]]; then
    echo -e "\n${CYAN}========== SMB SHARE ENUMERATION ==========${NC}"
    
    if [[ -f "$OUTPUT_DIR/computers.ldif" ]]; then
        COMPUTERS=$(grep "dNSHostName:" "$OUTPUT_DIR/computers.ldif" | sed 's/dNSHostName: //' | head -20)
        
        for computer in $COMPUTERS; do
            echo -e "${YELLOW}[*] Checking shares on $computer...${NC}"
            smbclient -L "\\\\$computer" -U "${DOMAIN}\\${USERNAME}%${PASSWORD}" -g 2>/dev/null | grep "Disk|" > "$OUTPUT_DIR/shares_${computer}.txt" || true
            
            if [[ -s "$OUTPUT_DIR/shares_${computer}.txt" ]]; then
                echo -e "${GREEN}[+] Shares found on $computer${NC}"
            fi
        done
    fi
fi

echo -e "\n${GREEN}========== ENUMERATION COMPLETE ==========${NC}"
echo -e "${CYAN}Results saved to: $OUTPUT_DIR/${NC}"
echo -e "${CYAN}Files generated:${NC}"
find "$OUTPUT_DIR" -type f -exec ls -lh {} \; | awk '{print $9, "(" $5 ")"}'

echo -e "\n${CYAN}Quick Stats:${NC}"
echo -e "Users: $(grep -c "^dn:" "$OUTPUT_DIR/users.ldif" 2>/dev/null || echo 0)"
echo -e "Groups: $(grep -c "^dn:" "$OUTPUT_DIR/groups.ldif" 2>/dev/null || echo 0)"
echo -e "Computers: $(grep -c "^dn:" "$OUTPUT_DIR/computers.ldif" 2>/dev/null || echo 0)"
echo -e "Trusts: $(grep -c "^dn:" "$OUTPUT_DIR/trusts.ldif" 2>/dev/null || echo 0)"
