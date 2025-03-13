#!/bin/bash

# Define the Nmap results file
RESULTS_FILE="scan_results.txt"

# Extract the target IP from the Nmap scan results
TARGET_IP=$(grep -oP 'Nmap scan report for \K[\d\.]+' "$RESULTS_FILE")

# Check if an IP was found
if [[ -z "$TARGET_IP" ]]; then
    echo "No target IP found in scan results. Exiting..."
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
	    echo "SMB service is open ... Enumerating SMB shares"
	    ;;

  	21)  
            echo "FTP detected - Checking for anonymous login..."        
		RESULTS_FILE="$1"
		USERNAME="anonymous"
		PASSWORD="anonymous"  

		TARGETS=$(awk '/Nmap scan report for/{ip=$5} /21\/tcp\s+open/{print ip}' "$RESULTS_FILE")

		if [ -z "$TARGETS" ]; then
  			echo "No valid IPs with open port 21 found in the Nmap scan results."
  			exit 1
		fi


		for TARGET in $TARGETS; do
  			ftp -inv "$TARGET" <<END_SCRIPT
user $USERNAME $PASSWORD
quit
END_SCRIPT
  
  			if [ $? -eq 0 ]; then
    				echo "FTP login successful on $TARGET."
    				break  # Exit the loop after successful connection
  			fi
		done

		echo "FTP test completed."

            	;;
        
        *)  
            	echo "No specific action defined for port $port" ;;
    esac
done

