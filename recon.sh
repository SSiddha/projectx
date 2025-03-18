#!/bin/bash

# Define the Nmap results file
RESULTS_FILE="scan_results.txt"
OUTPUT_FILE="final_results.txt"

#Colour codes                                                # Sorry, Colour blinds!!!
RED='\033[0;31m'    #Severe
YELLOW='\033[1;33m' #TMI - Too much information
GREEN='\033[0;32m'  #Harmless or (useless to us).
NC='\033[0m'        #Colour code to put the usual ink instead of other colours.

# Extract the target IP from the Nmap scan results
TARGET_IP=$(grep -oP 'Nmap scan report for \K[\d\.]+' "$RESULTS_FILE")

# Check if an IP was found
if [[ -z "$TARGET_IP" ]]; then
    echo "${GREEN}No target IP found in scan results. Exiting...${NC}"
    exit 1
fi

echo "Target IP: $TARGET_IP"

# Extract open ports from the results
OPEN_PORTS=$(grep -oP '^\d+/tcp\s+open' "$RESULTS_FILE" | awk -F/ '{print $1}')

# Loop through each open port and take action
for port in $OPEN_PORTS; do
    echo "Detected open port: $port on $TARGET_IP"
    
    case $port in
        22)  
            echo "SSH detected - Running Hydra for brute force testing..."
            hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/wordlists/rockyou.txt ssh://$TARGET_IP  ;;
        
        80|443)  
            echo "HTTP(S) detected - Running Gobuster for directory enumeration..."
            if [ $port -eq 80 ]; then
            gobuster dir -u http://$TARGET_IP/ -w /usr/share/wordlists/dirb/common.txt -t 100  -f -x pdf -b 403,404
            else
            gobuster dir -u https://$TARGET_IP/ -w /usr/share/wordlists/dirb/common.txt -t 100  -f -x pdf -b 403,404
            fi
            echo " VHOST(S) discovery ...."
            wfuzz -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -H "Host: FUZZ.$TARGET_IP" --hc 404 http://$TARGET_IP
	    echo "Performing extensive http(s) enumeration using  NMAP ...."
	    nmap -sV --script=http-enum -p80 $TARGET_IP;;
        
        3306)  
            echo "[+] Scanning MySQL on $TARGET_IP..."
	    nmap -p 3306 --open -sV --script=mysql* "$TARGET_IP"
	    echo "[+] Checking for Anonymous Login..."
	    nmap --script=mysql-empty-password -p 3306 "$TARGET_IP"
	    echo "[+] Attempting Brute Force with Hydra..."
	    hydra -L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/wordlists/rockyou.txt "$TARGET_IP" mysql -V 
	    echo "[+] Checking for MySQL Database Enumeration..."
	    nmap --script=mysql-databases -p 3306 "$TARGET_IP"
	    echo "[+] Checking for MySQL Users Enumeration..."
	    nmap --script=mysql-users -p 3306 "$TARGET_IP"
	    echo "[+] Checking for MySQL Weak Authentication..."
	    nmap --script=mysql-brute -p 3306 "$TARGET_IP"
	    echo "[+] Running SQL Injection Test with sqlmap..."
	    sqlmap -u "mysql://root@${TARGET_IP}/" --batch --dbs
	    echo "[+] Checking for MySQL Version Vulnerabilities..."
	    searchsploit mysql
	    echo "[+] Checking for Exploitable MySQL Misconfigurations with Metasploit..."
	    msfconsole -q -x "use auxiliary/scanner/mysql/mysql_schemadump; set RHOSTS $TARGET_IP; run; exit"
	    ;;
        
    139|445)
	    printf "\n\n${YELLOW}[+] SMB service is open and enumerating the shares...${NC}\n"
            nmap --script smb-enum-shares -p 139,445 $TARGET_IP
            printf "\n\n${YELLOW}[*] Looking for Eternal Blue vulnerability.........${NC}"
            nmap -p445 --script smb-vuln-ms17-010 $TARGET_IP  > temp.txt
            if grep -q "CVE-2017-0143" temp.txt; then
                printf "\n\n${RED}[+] Eternal Blue vulnerability is present${NC}\n";
            else
                printf "\n\n${GREEN}[-] Eternal Blue vulnerability is not present${NC}\n"
            fi
            rm temp.txt
	    enum4linux -U $TARGET_IP > temp.txt
            grep -Po '\[.*]' temp.txt | awk 'BEGIN{FS=" "} {print $1}' > temp2.txt
            if [ -s temp2.txt ]
            then
                printf "\n${YELLOW}The list of users found in this system...${NC}\n\n"
                while read user; do
                   printf "\n${RED}${user}${NC}"
                done <temp2.txt
            else
                printf "\n${GREEN}No users found in this system using SMB${NC}\n"
            fi
            rm temp.txt temp2.txt
	    printf "\n"
	    ;;

  	21)  
            echo "FTP detected - Checking for anonymous login..."        
		USERNAME="anonymous"
		PASSWORD="anonymous" 
		for TARGET in $TARGETS; do
  			ftp -inv "$TARGET" <<END_SCRIPT
user $USERNAME $PASSWORD
quit
END_SCRIPT
  
  			if [ $? -eq 0 ]; then
    				echo "${RED}FTP login successful on $TARGET.${NC}"
    				break  # Exit the loop after successful connection
  			fi
		done

		echo "FTP test completed."

            	;;
        
        *)  
            	echo "No specific action defined for port $port" ;;
    esac
done

