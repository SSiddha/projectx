#!/bin/bash

# Change interrupt key to Ctrl+X (ASCII 24)
stty intr ^X

# Trap SIGINT (now Ctrl+X)
trap "echo -e '\n\033[0;31mProcess interrupted. Exiting...\033[0m'; stty intr ^C; exit 1" SIGINT

# Files & Directories
RESULTS_FILE="scan_results.txt"
LOG_DIR="logs"
mkdir -p "$LOG_DIR"

# Colors
RED='\033[0;31m'    # Critical
YELLOW='\033[1;33m' # Warning
GREEN='\033[0;32m'  # Success
BLUE='\033[0;34m'   # Info
NC='\033[0m'        # No Color

# --- Filter Functions ---

filter_gobuster() {
    local log_file=$1
    echo -e "\n${BLUE}[+] Gobuster Results:${NC}"
    grep -E '^\/.* \(Status: (200|403)\)' "$log_file" | awk '{printf "%-40s %s\n", $1, $2}' || echo -e "${GREEN}No directories found.${NC}"
}

filter_hydra() {
    local log_file=$1
    echo -e "\n${BLUE}[+] Hydra Results:${NC}"
    if grep -q "login:" "$log_file"; then
        grep "login:" "$log_file" | awk -F"login:" '{print $2}' | sed 's/^[ \t]*//'
    else
        echo -e "${GREEN}No credentials found.${NC}"
    fi
}

filter_ffuf() {
    local log_file=$1
    echo -e "\n${BLUE}[+] FFUF Results:${NC}"
    if grep -q "\[Status:" "$log_file"; then
        grep "\[Status:" "$log_file" | awk '{printf "%-40s Status:%-5s Size:%-6s Words:%-5s\n", $1, $3, $5, $7}'
    else
        echo -e "${GREEN}No valid results.${NC}"
    fi
}

filter_wfuzz() {
    local log_file=$1
    echo -e "\n${BLUE}[+] Wfuzz Results (Valid Subdomains/VHOSTs):${NC}"
    if grep -q "00000" "$log_file"; then
        grep -v "404" "$log_file" | awk '/00000/ {print $2}' | sort -u
    else
        echo -e "${GREEN}No subdomains/VHOSTs found.${NC}"
    fi
}

filter_sqlmap() {
    local log_file=$1
    echo -e "\n${BLUE}[+] SQLMap Results:${NC}"
    
    # Extract databases
    if grep -q "available databases" "$log_file"; then
        echo -e "${YELLOW}=== Databases Found ===${NC}"
        sed -n '/available databases/,/^$/p' "$log_file" | grep -v "available databases" | sed '/^$/d'
    fi

    # Extract tables
    if grep -q "Database:" "$log_file"; then
        echo -e "\n${YELLOW}=== Tables Found ===${NC}"
        grep -A 100 "Database:" "$log_file" | grep -vE "^--$|^$"
    fi

    # Check for SQLi vulnerabilities
    if grep -q "is vulnerable" "$log_file"; then
        echo -e "\n${RED}=== Vulnerabilities ===${NC}"
        grep "is vulnerable" "$log_file"
    else
        echo -e "${GREEN}No SQL injection vulnerabilities found.${NC}"
    fi
}

# --- Main Script ---

TARGET_IP=$(grep -oP 'Nmap scan report for \K[\d\.]+' "$RESULTS_FILE" || echo "")
[[ -z "$TARGET_IP" ]] && { echo -e "${RED}No IP found. Exiting.${NC}"; exit 1; }

echo -e "${GREEN}Target IP: $TARGET_IP${NC}"
OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$RESULTS_FILE" | awk -F/ '{print $1}')

# Remove port 139 if 445 is open (SMB redundancy)
[[ "${OPEN_PORTS[@]}" =~ '139' && "${OPEN_PORTS[@]}" =~ '445' ]] && OPEN_PORTS=${OPEN_PORTS[@]/139/}

for port in $OPEN_PORTS; do
    LOG_FILE="$LOG_DIR/port_${port}.log"
    echo -e "\n${YELLOW}Scanning port $port...${NC}"

    case $port in
        22)  # SSH Port
            echo -e "${BLUE}[+] SSH detected. Running tests...${NC}" | tee -a "$LOG_FILE"
    
    # 1. Version/algorithm scan
            echo -e "\n${YELLOW}=== SSH Version Detection ===${NC}" | tee -a "$LOG_FILE"
            nmap -sV -p 22 --script=ssh2-enum-algos,ssh-auth-methods "$TARGET_IP" | tee -a "$LOG_FILE"
    
    # 2. Security audit (optional)
            if command -v ssh-audit &>/dev/null; then
                echo -e "\n${YELLOW}=== SSH Security Audit ===${NC}" | tee -a "$LOG_FILE"
                ssh-audit "$TARGET_IP" | tee -a "$LOG_FILE"
            else
                echo -e "${YELLOW}ssh-audit not installed. Skipping audit.${NC}" | tee -a "$LOG_FILE"
            fi
    # 3. Brute-force (user choice)
            read -p "Run Hydra brute-force attack? (Y/N): " choice
            if [[ "${choice^^}" == "Y" ]]; then
                echo -e "\n${RED}[!] WARNING: Brute-forcing may trigger locks!${NC}" | tee -a "$LOG_FILE"
                hydra -L /usr/share/wordlists/metasploit/unix_users.txt \
                  -P /usr/share/wordlists/rockyou.txt \
                  ssh://"$TARGET_IP" -t 4 -vV | tee -a "$LOG_FILE"
                filter_hydra "$LOG_FILE"  # <--- Filtering applied here!
            else
                echo -e "${GREEN}Skipping brute-force.${NC}" | tee -a "$LOG_FILE"
            fi
            ;;
            
        80|443)
            # Gobuster
            echo -e "${BLUE}Running Gobuster...${NC}"
            [[ $port -eq 80 ]] && url="http://$TARGET_IP/" || url="https://$TARGET_IP/"
            gobuster dir -u "$url" -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt -b 403,404 | tee -a "$LOG_FILE"
            filter_gobuster "$LOG_FILE"

            # FFUF
            echo -e "${BLUE}Running FFUF...${NC}"
            ffuf -u "${url}FUZZ" -w /usr/share/wordlists/dirb/common.txt -of csv -o "$LOG_DIR/ffuf_$port.csv" | tee -a "$LOG_FILE"
            filter_ffuf "$LOG_DIR/ffuf_$port.csv"

            # Wfuzz (VHOSTs)
            echo -e "${BLUE}Running Wfuzz for VHOSTs...${NC}"
            wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$TARGET_IP" --hc 404 "$url" | tee -a "$LOG_FILE"
            filter_wfuzz "$LOG_FILE"
            ;;

        3306)
            # SQLMap
            echo -e "${BLUE}Running SQLMap...${NC}"
            sqlmap -u "http://$TARGET_IP/" --batch --crawl=2 --level=3 --risk=2 | tee -a "$LOG_FILE"
            filter_sqlmap "$LOG_FILE"

            # Hydra (MySQL brute-force)
            read -p "Brute-force MySQL? (Y/N): " choice
            if [[ "${choice^^}" == "Y" ]]; then
                hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P /usr/share/wordlists/rockyou.txt "$TARGET_IP" mysql -t 4 -vV | tee -a "$LOG_FILE"
                filter_hydra "$LOG_FILE"
            fi
            ;;

        21)
            # FTP checks + Hydra
            echo -e "${BLUE}Checking FTP...${NC}"
            ftp -inv "$TARGET_IP" <<EOF | tee -a "$LOG_FILE"
user anonymous anonymous
quit
EOF
            [[ $? -eq 0 ]] && { echo -e "${RED}Anonymous FTP login allowed!${NC}"; }
            ;;
        
        53)
            # DNS Enumeration with Wfuzz
            echo -e "${BLUE}Running Wfuzz for DNS...${NC}"
            domain=$(dig -x "$TARGET_IP" +short | sed 's/\.$//')
            [[ -z "$domain" ]] && domain="$TARGET_IP"
            wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$domain" --hc 404 "http://$domain" | tee -a "$LOG_FILE"
            filter_wfuzz "$LOG_FILE"
            ;;

        *)
            echo -e "${GREEN}No automation for port $port.${NC}"
            ;;
    esac
done

# Restore Ctrl+C
stty intr ^C
echo -e "${GREEN}Scan completed. Logs saved in $LOG_DIR.${NC}"
