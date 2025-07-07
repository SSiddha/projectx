#!/bin/bash

# Change interrupt key to Ctrl+X (ASCII 24)
stty intr ^X

# Trap SIGINT (now Ctrl+X)
trap "echo -e '\n\033[0;31mProcess interrupted. Exiting...\033[0m'; stty intr ^C; exit 1" SIGINT

# Files & Directories
RESULTS_FILE="scan_results.txt"
LOG_DIR="logs"
FILTERS_DIR="./filters"
mkdir -p "$LOG_DIR"
USERLIST="/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

# -------- FUNCTIONS --------

run_hydra() {
    local service=$1
    local port=$2
    local protocol=$3

    local default_userlist="/usr/share/wordlists/metasploit/unix_users.txt"
    local default_passlist="/usr/share/wordlists/rockyou.txt"

    echo -e "\n${YELLOW}Hydra Brute-Force Options for $service:${NC}"
    echo -e "1. Use default wordlists"
    echo -e "2. Use custom wordlists"
    read -p "$(echo -e ${YELLOW}'Choose option (1/2): '${NC})" hydra_choice

    case $hydra_choice in
        1)
            userlist=$default_userlist
            passlist=$default_passlist
            ;;
        2)
            read -p "$(echo -e ${YELLOW}'Enter custom user wordlist: '${NC})" userlist
            read -p "$(echo -e ${YELLOW}'Enter custom password wordlist: '${NC})" passlist
            ;;
        *)
            echo -e "${RED}Invalid input, using default wordlists${NC}"
            userlist=$default_userlist
            passlist=$default_passlist
            ;;
    esac

    echo -e "${RED}[!] WARNING: Brute-forcing may trigger locks!${NC}"
    hydra -L "$userlist" -P "$passlist" "$protocol://$TARGET_IP:$port" -t 4 -vV > "$LOG_DIR/${service}_hydra.log" 2>&1

    if [ -f "$FILTERS_DIR/filter_hydra.sh" ]; then
        echo -e "\n${GREEN}[+] Filtered Hydra Results:${NC}"
        "$FILTERS_DIR/filter_hydra.sh" "$LOG_DIR/${service}_hydra.log"
    fi
}

get_service_name() {
    grep -P "^$1/tcp\s+open" "$RESULTS_FILE" | awk '{print $3}' || echo "unknown"
}

# -------- MAIN LOGIC --------

TARGET_IP=$(grep -oP 'Nmap scan report for \K[\d\.]+' "$RESULTS_FILE")
[[ -z "$TARGET_IP" ]] && { echo -e "${RED}No IP found. Exiting.${NC}"; exit 1; }

echo -e "${GREEN}Target IP: $TARGET_IP${NC}"
OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$RESULTS_FILE" | awk -F/ '{print $1}')
[[ "$OPEN_PORTS" =~ 139 ]] && [[ "$OPEN_PORTS" =~ 445 ]] && OPEN_PORTS=${OPEN_PORTS//139/}

for port in $OPEN_PORTS; do
    LOG_FILE="$LOG_DIR/port_${port}.log"
    SERVICE_NAME=$(get_service_name "$port")
    echo -e "\n${YELLOW}Scanning port $port ($SERVICE_NAME)...${NC}"

    case $port in
        21)
            echo -e "${BLUE}Checking FTP...${NC}"
            ftp -inv "$TARGET_IP" <<EOF | tee -a "$LOG_FILE"
user anonymous anonymous
quit
EOF
            [[ $? -eq 0 ]] && echo -e "${RED}Anonymous FTP login allowed!${NC}"

            read -p "$(echo -e ${YELLOW}'Run Hydra brute-force? (Y/N): '${NC})" choice
            [[ "${choice^^}" == "Y" ]] && run_hydra "ftp" "$port" "ftp"
            ;;

        22)
            echo -e "${BLUE}Running SSH scan...${NC}"
            nmap -sV -p 22 --script=ssh2-enum-algos,ssh-auth-methods "$TARGET_IP" -oN "$LOG_DIR/ssh_scan.log" >/dev/null 2>&1
            echo -e "${GREEN}SSH Version: $(grep -oP 'ssh.*' "$LOG_DIR/ssh_scan.log" | head -1)${NC}"

            read -p "$(echo -e ${YELLOW}'Run Hydra brute-force? (Y/N): '${NC})" choice
            [[ "${choice^^}" == "Y" ]] && run_hydra "ssh" "$port" "ssh"
            ;;

        23)
            echo -e "${BLUE}Telnet service detected...${NC}"
            read -p "$(echo -e ${YELLOW}'Run Hydra brute-force? (Y/N): '${NC})" choice
            [[ "${choice^^}" == "Y" ]] && run_hydra "telnet" "$port" "telnet"
            ;;

        25)
            echo -e "${BLUE}Testing SMTP VRFY and Open Relay...${NC}"
            while IFS= read -r user; do
                if echo "VRFY $user" | nc -w 5 "$TARGET_IP" 25 | grep -q "252"; then
                    echo "[+] SMTP User found: $user"
                fi
            done < "$USERLIST"

            relay_test=$(echo -e "MAIL FROM:<attacker@example.com>\nRCPT TO:<victim@example.com>\nQUIT" | nc -w 5 "$TARGET_IP" 25)
            if echo "$relay_test" | grep -q "Relaying denied"; then
                echo -e "${GREEN}[+] SMTP is not an open relay${NC}"
            else
                echo -e "${RED}[!] SMTP appears to be an open relay${NC}"
            fi
            ;;

        80|443|8000|8080|8443)
            echo -e "${BLUE}Scanning HTTP service on port $port...${NC}"
            [[ $port =~ ^(80|8000|8080)$ ]] && URL="http://$TARGET_IP:$port/" || URL="https://$TARGET_IP:$port/"

            gobuster dir -u "$URL" -w /usr/share/wordlists/dirb/common.txt \
                -t 50 -x php,html,txt -b 403,404 -q --no-color > "$LOG_DIR/gobuster_$port.log" 2>&1

            [ -f "$FILTERS_DIR/filter_gobuster.sh" ] && "$FILTERS_DIR/filter_gobuster.sh" "$LOG_DIR/gobuster_$port.log"

            echo -e "${BLUE}Running WhatWeb...${NC}"
            whatweb -a 3 "$URL" > "$LOG_DIR/whatweb_$port.log" 2>&1
            head -n 10 "$LOG_DIR/whatweb_$port.log" | grep -v "ERROR"

            echo -e "${BLUE}Checking for common files...${NC}"
            for f in robots.txt sitemap.xml crossdomain.xml .git/HEAD; do
                code=$(curl -s -o /dev/null -w "%{http_code}" "${URL}${f}")
                [[ "$code" == "200" ]] && echo -e "${GREEN}Found: ${URL}${f}${NC}"
            done
            ;;

        135)
            echo -e "${BLUE}Checking RPC Services...${NC}"
            rpcinfo -p "$TARGET_IP" > "$LOG_FILE" 2>/dev/null
            grep -q "100003" "$LOG_FILE" && echo -e "${RED}NFS Detected${NC}"
            grep -q "100005" "$LOG_FILE" && echo -e "${RED}Mountd Detected${NC}"
            grep -q "100000" "$LOG_FILE" && echo -e "${RED}Portmapper Detected${NC}"
            ;;

        139|445)
            echo -e "${BLUE}Enumerating SMB...${NC}"
            nmap --script smb-enum-shares -p 139,445 "$TARGET_IP" >> "$LOG_FILE"
            nmap -p 445 --script smb-vuln-ms17-010 "$TARGET_IP" >> "$LOG_FILE"

            enum4linux -U "$TARGET_IP" > temp.txt
            grep -Po '\[.*]' temp.txt | awk 'BEGIN{FS=" "} {print $1}' > temp2.txt
            if [ -s temp2.txt ]; then
                echo -e "${YELLOW}Users found:${NC}"
                cat temp2.txt | while read user; do echo -e "${RED}$user${NC}"; done
            else
                echo -e "${GREEN}No users found via SMB${NC}"
            fi
            rm temp.txt temp2.txt
            ;;

        3306)
            echo -e "${BLUE}Scanning MySQL...${NC}"
            nmap -p 3306 --script=mysql-info "$TARGET_IP" -oN "$LOG_DIR/mysql_service.log" >/dev/null 2>&1
            grep -q "mysql" "$LOG_DIR/mysql_service.log" && echo -e "${GREEN}MySQL Detected${NC}"

            declare -A creds=( ["root"]="root" ["root"]="" ["admin"]="admin" ["mysql"]="mysql" )
            for u in "${!creds[@]}"; do
                if mysql -h "$TARGET_IP" -u "$u" -p"${creds[$u]}" -e "SELECT 1" 2>/dev/null | grep -q 1; then
                    echo -e "${GREEN}Valid: $u:${creds[$u]}${NC}"
                    echo "$u:${creds[$u]}" >> "$LOG_DIR/mysql_creds.log"
                fi
            done

            read -p "$(echo -e ${YELLOW}'Test URL for SQLi (or Enter to skip): '${NC})" sqlmap_url
            if [ -n "$sqlmap_url" ]; then
                sqlmap -u "$sqlmap_url" --batch --level=3 --risk=2 --output-dir="$LOG_DIR/sqlmap" > "$LOG_DIR/sqlmap.log" 2>&1
                grep -q "is vulnerable" "$LOG_DIR/sqlmap.log" && echo -e "${RED}[!] SQL Injection Found${NC}" || echo -e "${GREEN}No SQLi detected${NC}"
            fi

            read -p "$(echo -e ${YELLOW}'Run Hydra brute-force? (Y/N): '${NC})" choice
            [[ "${choice^^}" == "Y" ]] && run_hydra "mysql" "$port" "mysql"
            ;;

        *)
            echo -e "${GREEN}No automation for port $port ($SERVICE_NAME)${NC}"
            ;;
    esac
done

# Restore Ctrl+C
stty intr ^C
echo -e "${GREEN}Scan completed. Logs saved in $LOG_DIR.${NC}"
