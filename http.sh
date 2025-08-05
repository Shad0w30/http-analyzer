#!/bin/bash

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Box Drawing Characters
TL='╔' # Top Left
TR='╗' # Top Right
BL='╚' # Bottom Left
BR='╝' # Bottom Right
HZ='═' # Horizontal
VT='║' # Vertical
LT='╠' # Left T
RT='╣' # Right T
TT='╦' # Top T
BT='╩' # Bottom T
CR='╬' # Cross

# Initialize variables
URL=""
REPORT_FILE="security_report_$(date +%Y%m%d_%H%M%S).txt"

# Print Table Function - Fixed version
print_table() {
    local -n headers=$1  # Use nameref for proper array passing
    local -n data=$2     # Use nameref for proper array passing
    local col_width=25
    
    # Table Header
    echo -e "${BLUE}${TL}$(printf '%*s' $(( (col_width + 2) * ${#headers[@]} )) | tr ' ' "${HZ}")${TR}${NC}"
    
    # Column Headers
    echo -ne "${BLUE}${VT}${NC}"
    for header in "${headers[@]}"; do
        printf " %-${col_width}s ${BLUE}${VT}${NC}" "${header}"
    done
    echo
    
    # Header Separator
    echo -ne "${BLUE}${LT}$(printf '%*s' $(( (col_width + 2) * ${#headers[@]} )) | tr ' ' "${HZ}")${RT}${NC}"
    echo
    
    # Table Data
    for row in "${data[@]}"; do
        echo -ne "${BLUE}${VT}${NC}"
        IFS='|' read -ra fields <<< "$row"
        for field in "${fields[@]}"; do
            printf " %-${col_width}s ${BLUE}${VT}${NC}" "${field}"
        done
        echo
    done
    
    # Table Footer
    echo -e "${BLUE}${BL}$(printf '%*s' $(( (col_width + 2) * ${#headers[@]} )) | tr ' ' "${HZ}")${BR}${NC}"
}

# Check HTTP Methods - Fixed version
check_http_methods() {
    local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE" "CONNECT")
    local results=()
    
    echo -e "${CYAN}Checking allowed HTTP methods for: ${URL}${NC}"
    
    for method in "${methods[@]}"; do
        response=$(curl -s -I -X "$method" --max-time 10 "$URL" 2>&1)
        
        if [[ "$response" =~ HTTP/.*[23][0-9][0-9] ]]; then
            status="${GREEN}Allowed${NC}"
            if [[ " PUT DELETE TRACE CONNECT " =~ " $method " ]]; then
                status="${YELLOW}Allowed (Risky)${NC}"
            fi
        else
            status="${RED}Blocked${NC}"
        fi
        
        results+=("${method}|${status}")
    done
    
    local headers=("HTTP Method" "Status")
    print_table headers results  # Fixed array passing
}

# Analyze Security Headers - Fixed version
analyze_security_headers() {
    local headers_list=(
        "Strict-Transport-Security"
        "X-Frame-Options"
        "X-Content-Type-Options"
        "Content-Security-Policy"
        "X-XSS-Protection"
        "Referrer-Policy"
        "Permissions-Policy"
        "Cache-Control"
        "Pragma"
    )
    local results=()
    
    response=$(curl -s -I --max-time 10 "$URL")
    
    for header in "${headers_list[@]}"; do
        if echo "$response" | grep -iq "^$header:"; then
            value=$(echo "$response" | grep -i "^$header:" | head -1 | cut -d':' -f2- | sed 's/^[ \t]*//')
            status="${GREEN}Present${NC}"
        else
            value=""
            status="${RED}Missing${NC}"
            if [[ " Strict-Transport-Security Content-Security-Policy X-Frame-Options " =~ " $header " ]]; then
                status="${YELLOW}Missing (Critical)${NC}"
            fi
        fi
        results+=("${header}|${status}|${value:0:30}")
    done
    
    local headers=("Security Header" "Status" "Value (truncated)")
    print_table headers results  # Fixed array passing
}

# [Rest of the functions remain the same as in the previous complete version]
# [Include examine_cookies, probe_resources, export_report, show_menu, and main]

# Main Function
main() {
    if [ -z "$1" ]; then
        echo -e "${CYAN}Enter target URL: ${NC}"
        read -r URL
    else
        URL="$1"
    fi
    
    # Remove trailing slash
    URL="${URL%/}"
    
    while true; do
        show_menu
        echo -e "${CYAN}Select an option (1-8): ${NC}"
        read -r choice
        
        case "$choice" in
            1)
                check_http_methods
                analyze_security_headers
                examine_cookies
                probe_resources
                ;;
            2) check_http_methods ;;
            3) analyze_security_headers ;;
            4) examine_cookies ;;
            5) probe_resources ;;
            6)
                echo -e "${CYAN}Enter new target URL: ${NC}"
                read -r URL
                URL="${URL%/}"
                ;;
            7) export_report ;;
            8) exit 0 ;;
            *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
        esac
        
        echo -e "\n${CYAN}Press [Enter] to continue...${NC}"
        read -r
    done
}

# Start the script
main "$@"