#!/bin/bash

# version 18 - added -i option to fetch IP info from ipinfo.io
### 'geoip --help' - display help information

# Function to generate a list of 30 IPs from a given subnet
generate_ips_from_subnet() {
    local subnet=$1
    local base_ip=$(echo $subnet | cut -d'/' -f1)
    local prefix=$(echo $subnet | cut -d'/' -f2)
    local base_num=$(echo $base_ip | awk -F. '{print ($1 * 256^3) + ($2 * 256^2) + ($3 * 256) + $4}')
    local start_num=$((($base_num / 256) * 256))

    for i in {0..29}; do
        local ip_num=$(($start_num + ($i * 8) % 256))
        local ip=$(printf "%d.%d.%d.%d" $(($ip_num >> 24 & 255)) $(($ip_num >> 16 & 255)) $(($ip_num >> 8 & 255)) $(($ip_num & 255)))
        echo $ip
    done
}

# Display help information
display_help() {
    echo "##############################################"
    echo "Usage: $0 [OPTIONS] [DIG OPTIONS]"
    echo "##############################################"
    echo
    echo "This program allows you to paste blocks of text and do the following:"
    echo "  geoip          - perform WHOIS lookups for all IPs in text"
    echo "  geoip -f       - format all IPs in text into a readable list"
    echo "  geoip -d       - dig CNAMEs of all domains in text"
    echo "  geoip -i       - fetch IP info from ipinfo.io"
    echo "  geoip --help   - display this help information"
    echo
    echo "Examples:"
    echo "##############################################"
    echo "  $0             # Run the script to process IPs for geolocation"
    echo "  $0 -f          # Reformat the list of IP addresses"
    echo "  $0 -d ns +answer  # Dig CNAMEs and pass additional options to dig"
    echo "  $0 -d +noshort  # Dig CNAMEs without +short"
    echo "  $0 -i          # Fetch IP info from ipinfo.io"
    echo "##############################################"
    echo
}

# Parse command-line options
format_only=false
dig_cnames=false
fetch_ip_info=false
dig_options=()
add_short=true  # New variable to track whether to add +short

while getopts ":fdhi-:" opt; do
    case ${opt} in
        f ) format_only=true ;;
        d ) dig_cnames=true ;;
        i ) fetch_ip_info=true ;;
        h ) display_help; exit 0 ;;
        - ) 
            case "${OPTARG}" in
                help ) display_help; exit 0 ;;
                * ) dig_options+=("--${OPTARG}") ;;
            esac
            ;;
        * ) dig_options+=("-${opt}${OPTARG}") ;;
    esac
done
shift $((OPTIND -1))

# Collect remaining arguments as dig options
dig_options+=("$@")

# Check if +noshort is present in the options
for opt in "${dig_options[@]}"; do  # New loop to check for +noshort
    if [[ "$opt" == "+noshort" ]]; then
        add_short=false
        dig_options=("${dig_options[@]/$opt}")  # Remove +noshort from the options
        break
    fi
done

# Remove any empty options that might have been added
dig_options=($(echo "${dig_options[@]}" | tr ' ' '\n' | grep -v '^$'))

# ///////////////////////////////////////////////////////////////////////////////////////////
# begin reading text

# Prompt the user to enter any text containing IP addresses or CNAMEs
echo "Enter text containing IP addresses or CNAMEs (end input with '~' on a new line):"
echo ""
echo "To use geolocation functionality, please make sure JSON Query (jq) is installed"
input=""
while IFS= read -r line; do
    if [[ "$line" == *"~"* ]]; then
        input+="${line%%~*}"
        break
    fi
    input+="$line"$'\n'
done

# Adding space to separate input text from output text
echo "####################################### Processing #######################################"
echo ""

# Extract all unique IP addresses (IPv4) from the input
ips=$(echo "$input" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | awk '!seen[$0]++')

# Format IP addresses if -f option is set
if [ "$format_only" = true ]; then
    echo "Reformatted IP addresses:"
    echo "$ips"
    exit 0
fi

# Fetch IP info from ipinfo.io if -i option is set
if [ "$fetch_ip_info" = true ]; then
    echo "Fetching IP info from ipinfo.io:"
    for ip in $ips; do
        RESPONSE=$(curl -s "https://ipinfo.io/$ip/json")
        CITY=$(echo "$RESPONSE" | jq -r '.city')
        REGION=$(echo "$RESPONSE" | jq -r '.region')
        COUNTRY=$(echo "$RESPONSE" | jq -r '.country')
        ORG=$(echo "$RESPONSE" | jq -r '.org')
        echo "$ip: $CITY: $REGION: $COUNTRY: \"org\": $ORG"
    done
    exit 0
fi

# Dig CNAMEs if -d option is set
if [ "$dig_cnames" = true ]; then
    echo "Performing dig on CNAMEs:"
    cnames=$(echo "$input" | grep -oE '\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b' | awk '!seen[$0]++')
    for cname in $cnames; do
        if [ "$add_short" = true ]; then  # Conditional logic to handle +short
            echo "dig +short ${dig_options[*]} $cname"
            dig +short "${dig_options[@]}" $cname
        else
            echo "dig ${dig_options[*]} $cname"
            dig "${dig_options[@]}" $cname
        fi
        echo
    done
    exit 0
fi

# Extract all IP addresses (IPv4 and IPv6) and subnets from the input
ips=$(echo "$input" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}(:[0-9]{1,5})?(\/[0-9]{1,2})?\b|\b([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}(\/[0-9]{1,3})?\b')

# Check if any IP addresses were found
if [ -z "$ips" ]; then
    echo "No IP addresses found in the input."
    exit 1
fi

# Determine if a single IP with subnet was provided
single_ip_with_subnet=$(echo "$ips" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}\/[0-9]{1,2}$' | wc -l)
total_ips=$(echo "$ips" | wc -l)

# Process the IPs
for entry in $ips; do
    # Remove port numbers from IPv4 addresses
    if [[ "$entry" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}:[0-9]{1,5}$ ]]; then
        entry=$(echo $entry | sed 's/:[0-9]*$//g')
    fi

    if [[ $single_ip_with_subnet -eq 1 && $total_ips -eq 1 && $entry == *"/"* ]]; then
        # If a single IPv4 with subnet is provided
        ip_list=$(generate_ips_from_subnet $entry)
    else
        # If entry is a single IP address or multiple IPs with subnets
        ip_list=$(echo $entry | sed 's/\/[0-9]*//g')
    fi

    for IP in $ip_list; do
        echo "WHOIS information for $IP:"
        whois "$IP" | grep -E "OrgName|Country|NetName|ASName"  # Extract useful information
        echo
    done
done