#!/bin/bash

# Color Definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Initialize variables
URL=""
REPORT_FILE="security_report_$(date +%Y%m%d_%H%M%S).txt"

# Verify URL format
verify_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        url="https://$url"
    fi
    # Remove trailing slash
    url="${url%/}"
    echo "$url"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Print section header
print_header() {
    echo -e "\n${BLUE}=== $1 ===${NC}"
}

# Verify curl connectivity
verify_connectivity() {
    if ! curl -s -I --connect-timeout 10 "$URL" >/dev/null; then
        echo -e "${RED}Error: Could not connect to $URL${NC}"
        echo -e "${YELLOW}Please check:${NC}"
        echo "1. The URL is correct"
        echo "2. The server is reachable"
        echo "3. You have internet connectivity"
        return 1
    fi
    return 0
}

# Check HTTP Methods
check_http_methods() {
    print_header "HTTP METHODS CHECK"
    if ! verify_connectivity; then return; fi

    local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE" "CONNECT")
    
    for method in "${methods[@]}"; do
        if response=$(curl -s -I -X "$method" --max-time 10 "$URL" 2>/dev/null); then
            if [[ "$response" =~ HTTP/.*[23][0-9][0-9] ]]; then
                echo -e "${method}: ${GREEN}Allowed${NC}"
                if [[ " PUT DELETE TRACE CONNECT " =~ " $method " ]]; then
                    echo -e "${YELLOW}  Warning: Potentially dangerous method allowed${NC}"
                fi
            else
                echo -e "${method}: ${RED}Blocked${NC}"
            fi
        else
            echo -e "${method}: ${RED}Failed to test${NC}"
        fi
    done
}

# Analyze Security Headers
analyze_security_headers() {
    print_header "SECURITY HEADERS CHECK"
    if ! verify_connectivity; then return; fi

    local headers=(
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
    
    if response=$(curl -s -I --max-time 10 "$URL"); then
        for header in "${headers[@]}"; do
            if echo "$response" | grep -iq "^$header:"; then
                value=$(echo "$response" | grep -i "^$header:" | head -1 | cut -d':' -f2- | sed 's/^[ \t]*//')
                echo -e "${header}: ${GREEN}Present${NC}"
                echo -e "  Value: ${value:0:50}"
            else
                echo -e "${header}: ${RED}Missing${NC}"
                if [[ " Strict-Transport-Security Content-Security-Policy X-Frame-Options " =~ " $header " ]]; then
                    echo -e "${YELLOW}  Warning: Critical security header missing${NC}"
                fi
            fi
        done
    else
        echo -e "${RED}Failed to retrieve headers${NC}"
    fi
}

# Examine Cookies
examine_cookies() {
    print_header "COOKIE ANALYSIS"
    if ! verify_connectivity; then return; fi

    if cookies=$(curl -s -I -v --max-time 10 "$URL" 2>&1 | grep -i "^< set-cookie:"); then
        if [ -z "$cookies" ]; then
            echo -e "${GREEN}No cookies found${NC}"
        else
            while IFS= read -r cookie; do
                cookie=$(echo "$cookie" | tr -d '\r')
                echo -e "\n${BLUE}Cookie:${NC} $(echo "$cookie" | cut -d':' -f2- | cut -d';' -f1)"
                
                if echo "$cookie" | grep -iq "Secure"; then
                    echo -e "  Secure: ${GREEN}Yes${NC}"
                else
                    echo -e "  Secure: ${RED}No${NC}"
                fi
                
                if echo "$cookie" | grep -iq "HttpOnly"; then
                    echo -e "  HttpOnly: ${GREEN}Yes${NC}"
                else
                    echo -e "  HttpOnly: ${RED}No${NC}"
                fi
                
                if echo "$cookie" | grep -iq "SameSite"; then
                    samesite=$(echo "$cookie" | grep -io "SameSite=[^;]*" | cut -d'=' -f2)
                    echo -e "  SameSite: ${GREEN}${samesite}${NC}"
                else
                    echo -e "  SameSite: ${RED}None${NC}"
                fi
            done <<< "$cookies"
        fi
    else
        echo -e "${RED}Failed to retrieve cookies${NC}"
    fi
}

# Probe Common Resources
probe_resources() {
    print_header "RESOURCE PROBE"
    if ! verify_connectivity; then return; fi

    local resources=(
        "/robots.txt"
        "/sitemap.xml"
        "/admin"
        "/wp-admin"
        "/login"
        "/api"
        "/.git/HEAD"
        "/.env"
        "/backup"
        "/test"
        "/phpinfo.php"
    )
    
    for resource in "${resources[@]}"; do
        full_url="${URL}${resource}"
        if response=$(curl -s -I -o /dev/null -w "%{http_code}" --connect-timeout 5 "$full_url" 2>/dev/null); then
            case "$response" in
                200) status="${GREEN}Found${NC}" ;;
                301|302) status="${CYAN}Redirect${NC}" ;;
                403) status="${YELLOW}Forbidden${NC}" ;;
                404) status="${RED}Not Found${NC}" ;;
                500) status="${RED}Server Error${NC}" ;;
                *) status="${YELLOW}Unknown (${response})${NC}" ;;
            esac
            
            echo -e "${resource}: ${status}"
            
            if [[ "$response" == "200" && "$resource" =~ ^/(admin|wp-admin|.env|.git|phpinfo.php) ]]; then
                echo -e "${YELLOW}  Warning: Sensitive resource found${NC}"
            fi
        else
            echo -e "${resource}: ${RED}Failed to test${NC}"
        fi
    done
}

# TLS/SSL Scan
scan_tls() {
    print_header "TLS/SSL SCAN"
    
    if ! command_exists openssl; then
        echo -e "${RED}OpenSSL not found. TLS scan skipped.${NC}"
        return
    fi
    
    local host=$(echo "$URL" | awk -F/ '{print $3}')
    local port=443
    
    if [ -z "$host" ]; then
        echo -e "${RED}Invalid hostname extracted from URL${NC}"
        return
    fi
    
    echo -e "Scanning ${CYAN}$host:$port${NC}"
    
    # Test basic connection
    if ! openssl s_client -connect "$host:$port" -servername "$host" < /dev/null 2>/dev/null | grep -q 'CONNECTED'; then
        echo -e "${RED}Failed to establish SSL connection${NC}"
        return
    fi
    
    # Certificate info
    echo -e "\n${BLUE}Certificate Information:${NC}"
    openssl s_client -connect "$host:$port" -servername "$host" < /dev/null 2>/dev/null | \
    openssl x509 -noout -text | grep -E 'Issuer:|Subject:|Not Before:|Not After :|DNS:' || \
    echo -e "${RED}Failed to retrieve certificate info${NC}"
    
    # Protocol support
    echo -e "\n${BLUE}Supported Protocols:${NC}"
    local protocols=("ssl2" "ssl3" "tls1" "tls1_1" "tls1_2" "tls1_3")
    for proto in "${protocols[@]}"; do
        if openssl s_client -connect "$host:$port" -"$proto" < /dev/null 2>/dev/null | grep -q 'CONNECTED'; then
            echo -e "$proto: ${GREEN}Supported${NC}"
        else
            echo -e "$proto: ${RED}Not supported${NC}"
        fi
    done
    
    # Cipher suites
    echo -e "\n${BLUE}Cipher Suite Check (first 10):${NC}"
    openssl ciphers 'ALL:eNULL' | sed 's/:/ /g' | while read -r cipher; do
        if openssl s_client -connect "$host:$port" -cipher "$cipher" < /dev/null 2>/dev/null | grep -q 'Cipher is'; then
            echo -e "$cipher: ${GREEN}Available${NC}"
        fi
    done | head -10
}

# Export Report
export_report() {
    {
        echo "Security Report for: ${URL}"
        echo "Generated on: $(date)"
        echo ""
        echo "=== HTTP Methods ==="
        check_http_methods | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'
        echo ""
        echo "=== Security Headers ==="
        analyze_security_headers | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'
        echo ""
        echo "=== Cookies ==="
        examine_cookies | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'
        echo ""
        echo "=== Resource Probe ==="
        probe_resources | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'
        echo ""
        echo "=== TLS/SSL Scan ==="
        scan_tls | sed 's/\x1B\[[0-9;]*[a-zA-Z]//g'
    } > "$REPORT_FILE"
    
    echo -e "\n${GREEN}Report saved to: ${REPORT_FILE}${NC}"
}

# Show Menu
show_menu() {
    clear
    echo -e "${BLUE}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║           WEB SECURITY ANALYZER             ║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║  Target: ${CYAN}$(printf "%-40s" "${URL}")${BLUE}║${NC}"
    echo -e "${BLUE}╠══════════════════════════════════════════════╣${NC}"
    echo -e "${BLUE}║  1. Run Full Security Scan                  ║${NC}"
    echo -e "${BLUE}║  2. Check HTTP Methods                      ║${NC}"
    echo -e "${BLUE}║  3. Analyze Security Headers                ║${NC}"
    echo -e "${BLUE}║  4. Examine Cookies                         ║${NC}"
    echo -e "${BLUE}║  5. Probe Common Resources                  ║${NC}"
    echo -e "${BLUE}║  6. Scan TLS/SSL Configuration              ║${NC}"
    echo -e "${BLUE}║  7. Change Target URL                       ║${NC}"
    echo -e "${BLUE}║  8. Export Report                           ║${NC}"
    echo -e "${BLUE}║  9. Exit                                    ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════╝${NC}"
}

# Main Function
main() {
    if [ -z "$1" ]; then
        echo -e "${CYAN}Enter target URL: ${NC}"
        read -r URL
    else
        URL="$1"
    fi
    
    URL=$(verify_url "$URL")
    
    while true; do
        show_menu
        echo -e "${CYAN}Select an option (1-9): ${NC}"
        read -r choice
        
        case "$choice" in
            1)
                check_http_methods
                analyze_security_headers
                examine_cookies
                probe_resources
                scan_tls
                ;;
            2) check_http_methods ;;
            3) analyze_security_headers ;;
            4) examine_cookies ;;
            5) probe_resources ;;
            6) scan_tls ;;
            7)
                echo -e "${CYAN}Enter new target URL: ${NC}"
                read -r URL
                URL=$(verify_url "$URL")
                ;;
            8) export_report ;;
            9) exit 0 ;;
            *) echo -e "${RED}Invalid option. Please try again.${NC}" ;;
        esac
        
        echo -e "\n${CYAN}Press [Enter] to continue...${NC}"
        read -r
    done
}

# Start the script
main "$@"
