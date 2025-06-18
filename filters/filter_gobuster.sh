#!/bin/bash

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

filter_gobuster() {
    local log_file=$1
    echo -e "\n${GREEN}[+] Gobuster Results (200/301/403):${NC}"
    
    # Extract lines with status codes, normalize spacing, and clean output
    results=$(grep -E '\(Status: (200|301|403)\)' "$log_file" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    
    if [ -n "$results" ]; then
        echo "$results" | awk '{
            # Flexible matching for paths with varying indentation
            if (match($0, /([^ ]+)[[:space:]]+\(Status: ([0-9]+)\)/, arr)) {
                status = arr[2];
                color = (status == "200") ? "'${GREEN}'" : 
                       (status == "301") ? "'${BLUE}'" : "'${YELLOW}'";
                printf "%-25s " color "(Status: %s)'${NC}'\n", arr[1], status
            }
        }' | sort -u
    else
        echo -e "${YELLOW}No accessible directories found.${NC}"
    fi
}

[[ -f "$1" ]] && filter_gobuster "$1"
