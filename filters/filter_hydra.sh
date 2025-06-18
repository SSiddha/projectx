#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

filter_hydra() {
    local log_file=$1
    echo -e "\n${GREEN}[+] Hydra Credentials Found:${NC}"
    
    # Extract credentials for any service
    results=$(
        # Standard format: [port][service] host: IP login: user password: pass
        grep -E '^\[[0-9]+\]\[[a-z]+\] host:' "$log_file" |
        # Compact format: [port][service] host=IP login=user password=pass
        sed -E 's/^.*(login:|login=)\s*//; s/\s*(password:|password=)\s*/:/' |
        sort -u
    )
    
    if [ -n "$results" ]; then
        echo -e "${GREEN}Service\t\tUsername\t\tPassword${NC}"
        echo -e "-------\t\t--------\t\t--------"
        awk -F: '{
            # Extract service from original line
            if (match($0, /\[[0-9]+\]\[([a-z]+)\]/, srv)) {
                service = srv[1]
            }
            printf "'${YELLOW}'%-8s'${NC}' \t'${GREEN}'%-16s'${NC}' \t'${RED}'%-16s'${NC}'\n", 
                service, $1, $2
        }' <<< "$results"
    else
        echo -e "${YELLOW}No valid credentials found.${NC}"
    fi
}

[[ -f "$1" ]] && filter_hydra "$1"
