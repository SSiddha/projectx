#!/bin/bash

# Define the Nmap results file
RESULTS_FILE="scan_results.txt"

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
            ;;
        
        3306)  
            echo "MySQL detected - Checking for anonymous access..."
            ;;
        
    139|445)
	    printf "\n\n${YELLOW}[+] SMB service is open and enumerating the shares...${NC}\n"
            nmap --script smb-enum-shares -p 139,445 $TARGET_IP
            printf "\n\n${YELLOW}[*] Looking for Eternal Blue vulnerability.........${NC}"
            nmap -p445 --script smb-vuln-ms17-010 $TARGET_IP  > temp.txt
            if grep -q "CVE-2017-0143" temp.txt; then
                printf "\n\n${RED}[+] Eternal Blue vulnerability is present${NC}";
            else
                printf "\n\n${GREEN}[-] Eternal Blue vulnerability is not present${NC}"
            fi
            rm temp.txt
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

