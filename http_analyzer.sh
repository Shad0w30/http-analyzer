#!/bin/bash

# Color printing function - must be defined first
color_print() {
    local color="$1"
    local message="$2"
    
    case "$color" in
        red)    color_code="\033[31m" ;;
        green)  color_code="\033[32m" ;;
        yellow) color_code="\033[33m" ;;
        blue)   color_code="\033[34m" ;;
        *)      color_code="" ;;
    esac
    
    echo -e "${color_code}${message}\033[0m"
}

# Check dependencies
check_dependencies() {
    local missing=()
    
    if ! command -v curl &> /dev/null; then
        missing+=("curl")
    fi
    
    if [ "$1" = "pdf" ] && ! command -v pandoc &> /dev/null; then
        missing+=("pandoc (for PDF export)")
    fi
    
    if [ "$1" = "excel" ] && ! command -v python3 &> /dev/null; then
        missing+=("python3 (for Excel export)")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        color_print "red" "Error: Missing dependencies: ${missing[*]}"
        return 1
    fi
    return 0
}

# Initialize report data
init_report() {
    declare -gA REPORT_DATA
    REPORT_DATA=(
        ["url"]="$URL"
        ["date"]="$(date +'%Y-%m-%d %H:%M:%S')"
        ["http_methods"]=""
        ["security_headers"]=""
        ["cookies"]=""
        ["resources"]=""
    )
}

# HTTP Methods check
check_http_methods() {
    local url="$1"
    local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD" "TRACE" "CONNECT")
    local allowed_methods=()
    
    color_print "blue" "\n[+] Checking allowed HTTP methods for $url"
    
    for method in "${methods[@]}"; do
        response=$(curl -s -I -X "$method" --max-time 10 "$url" 2>&1)
        
        if [[ "$response" =~ HTTP/.*[23][0-9][0-9] ]]; then
            allowed_methods+=("$method")
            
            if [ "$method" = "OPTIONS" ]; then
                allow_header=$(echo "$response" | grep -i "^Allow:" | tr -d '\r')
                if [ -n "$allow_header" ]; then
                    color_print "green" "  [*] $allow_header"
                fi
            fi
        fi
    done
    
    if [ ${#allowed_methods[@]} -eq 0 ]; then
        color_print "red" "  [-] No HTTP methods allowed or site not reachable"
    else
        color_print "green" "  [+] Allowed methods: ${allowed_methods[*]}"
        
        local dangerous_methods=("PUT" "DELETE" "TRACE" "CONNECT")
        for method in "${dangerous_methods[@]}"; do
            if [[ " ${allowed_methods[*]} " =~ " $method " ]]; then
                color_print "red" "  [!] Potentially dangerous method allowed: $method"
            fi
        done
    fi
    
    # Store in report
    REPORT_DATA["http_methods"]="${allowed_methods[*]}"
}

# Security Headers check
analyze_security_headers() {
    local url="$1"
    local headers=("Strict-Transport-Security" "X-Frame-Options" "X-Content-Type-Options" 
                  "Content-Security-Policy" "X-XSS-Protection" "Referrer-Policy" 
                  "Permissions-Policy" "Feature-Policy" "Cache-Control" "Pragma" "Expires")
    
    color_print "blue" "\n[+] Security Headers Analysis"
    
    response=$(curl -s -I --max-time 10 "$url")
    local headers_found=()
    local headers_missing=()
    
    for header in "${headers[@]}"; do
        if echo "$response" | grep -iq "^$header:"; then
            header_value=$(echo "$response" | grep -i "^$header:" | head -1 | tr -d '\r' | cut -d':' -f2- | sed 's/^[ \t]*//')
            color_print "green" "  [+] $header: $header_value"
            headers_found+=("$header: $header_value")
        else
            color_print "red" "  [-] Missing: $header"
            headers_missing+=("$header")
        fi
    done
    
    # Store in report
    REPORT_DATA["security_headers_found"]="${headers_found[*]}"
    REPORT_DATA["security_headers_missing"]="${headers_missing[*]}"
}

# Cookie analysis
examine_cookies() {
    local url="$1"
    
    color_print "blue" "\n[+] Cookie Analysis"
    
    cookies=$(curl -s -I -v --max-time 10 "$url" 2>&1 | grep -i "^< set-cookie:")
    local cookie_data=()
    
    if [ -z "$cookies" ]; then
        color_print "green" "  [+] No cookies found"
    else
        while IFS= read -r cookie; do
            cookie=$(echo "$cookie" | tr -d '\r')
            color_print "blue" "  [*] Cookie: $(echo "$cookie" | cut -d':' -f2- | cut -d';' -f1)"
            cookie_data+=("$cookie")
            
            # Check attributes
            if ! echo "$cookie" | grep -iq "Secure"; then
                color_print "red" "    [-] Missing Secure flag"
            fi
            
            if ! echo "$cookie" | grep -iq "HttpOnly"; then
                color_print "red" "    [-] Missing HttpOnly flag"
            fi
            
            if ! echo "$cookie" | grep -iq "SameSite"; then
                color_print "red" "    [-] Missing SameSite attribute"
            fi
        done <<< "$cookies"
    fi
    
    # Store in report
    REPORT_DATA["cookies"]="${cookie_data[*]}"
}

# Common resources check
probe_resources() {
    local base_url="$1"
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
    
    color_print "blue" "\n[+] Checking common resources"
    local resource_results=()
    
    for resource in "${resources[@]}"; do
        full_url="${base_url}${resource}"
        response=$(curl -s -I -o /dev/null -w "%{http_code}" --connect-timeout 5 "$full_url")
        
        case "$response" in
            200|301|302) status="Found ($response)" ;;
            403) status="Forbidden ($response)" ;;
            404) status="Not Found ($response)" ;;
            *) status="Unknown response ($response)" ;;
        esac
        
        color_print "blue" "  [*] $resource: $status"
        resource_results+=("$resource: $status")
    done
    
    # Store in report
    REPORT_DATA["resources"]="${resource_results[*]}"
}

# Full scan
run_full_scan() {
    color_print "blue" "\nRunning full security scan for: $URL"
    check_http_methods "$URL"
    analyze_security_headers "$URL"
    examine_cookies "$URL"
    probe_resources "$URL"
}

# Change URL
change_url() {
    read -p "Enter new target URL: " new_url
    URL="${new_url%/}"
    color_print "green" "Target URL changed to: $URL"
    init_report
}

# Export functions
export_report() {
    case "$1" in
        json)
            echo "${REPORT_DATA[@]}" | jq -n 'inputs' > "security_report_$(date +%Y%m%d_%H%M%S).json"
            color_print "green" "JSON report generated"
            ;;
        excel)
            check_dependencies "excel" || return
            # Create temporary JSON file
            echo "${REPORT_DATA[@]}" | jq -n 'inputs' > security_report.json
            python3 -c "
import pandas as pd
import json
with open('security_report.json') as f:
    data = json.load(f)
df = pd.DataFrame.from_dict(data, orient='index')
df.to_excel('security_report_$(date +%Y%m%d_%H%M%S).xlsx', index=True)
"
            color_print "green" "Excel report generated"
            ;;
        pdf)
            check_dependencies "pdf" || return
            # Create temporary JSON file
            echo "${REPORT_DATA[@]}" | jq -n 'inputs' > security_report.json
            pandoc security_report.json -o "security_report_$(date +%Y%m%d_%H%M%S).pdf"
            color_print "green" "PDF report generated"
            ;;
        *)
            color_print "red" "Invalid export format"
            ;;
    esac
}

# Main menu
show_menu() {
    clear
    color_print "blue" "=============================================="
    color_print "blue" "       Web Security Analyzer - Main Menu      "
    color_print "blue" "=============================================="
    color_print "blue" "Current Target: $URL"
    echo ""
    color_print "green" "1. Run Full Security Scan"
    color_print "green" "2. Check HTTP Methods"
    color_print "green" "3. Analyze Security Headers"
    color_print "green" "4. Examine Cookies"
    color_print "green" "5. Probe Common Resources"
    color_print "yellow" "6. Change Target URL"
    color_print "blue" "7. Export Report"
    color_print "red" "8. Exit"
    echo ""
}

# Export menu
export_menu() {
    clear
    color_print "blue" "=============================================="
    color_print "blue" "             Export Report Options           "
    color_print "blue" "=============================================="
    echo ""
    color_print "green" "1. Export as JSON"
    color_print "green" "2. Export as Excel (requires python3)"
    color_print "green" "3. Export as PDF (requires pandoc)"
    color_print "yellow" "4. Back to Main Menu"
    echo ""
    
    read -p "Select export format (1-4): " export_choice
    
    case "$export_choice" in
        1) export_report "json" ;;
        2) export_report "excel" ;;
        3) export_report "pdf" ;;
        4) return ;;
        *) color_print "red" "Invalid option" ;;
    esac
}

# Interactive loop
interactive_loop() {
    while true; do
        show_menu
        read -p "Select an option (1-8): " choice
        
        case "$choice" in
            1) run_full_scan ;;
            2) check_http_methods "$URL" ;;
            3) analyze_security_headers "$URL" ;;
            4) examine_cookies "$URL" ;;
            5) probe_resources "$URL" ;;
            6) change_url ;;
            7) export_menu ;;
            8) exit 0 ;;
            *) color_print "red" "Invalid option. Please try again." ;;
        esac
        
        read -p "Press [Enter] to continue..."
    done
}

# Main execution
main() {
    if [ -z "$1" ]; then
        read -p "Enter target URL: " URL
    else
        URL="$1"
    fi
    
    # Remove trailing slash if present
    URL="${URL%/}"
    
    # Initialize report
    init_report
    
    # Start interactive session
    interactive_loop
}

main "$@"