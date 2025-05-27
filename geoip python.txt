import argparse
import requests
import re
import subprocess
from ipaddress import ip_network, ip_address

def generate_ips_from_subnet(subnet):
    """Generate a list of 30 IPs from a given subnet."""
    network = ip_network(subnet, strict=False)
    base_ip = network.network_address
    ips = [str(ip_address(int(base_ip) + (i * 8 % 256))) for i in range(30)]
    return ips

def display_help():
    """Display help information."""
    help_text = """
##############################################
Usage: geoip.py [OPTIONS]
##############################################

This program allows you to paste blocks of text and do the following:
  geoip           - get geolocation of all IPs in text
                    http://test.vo.llnwd.net/geoipquery/?ip=
  geoip -f        - format all IPs in text into a readable list
  geoip -d        - dig CNAMEs of all domains in text
  geoip -i        - fetch IP info from ipinfo.io
  geoip -h --help - display this help information

Examples:
##############################################
  geoip.py             # Run the script to process IPs for geolocation
  geoip.py -f          # Reformat the list of IP addresses
  geoip.py -d ns +answer  # Dig CNAMEs and pass additional options to dig
  geoip.py -d +noshort  # Dig CNAMEs without +short
  geoip.py -i          # Fetch IP info from ipinfo.io
##############################################
    """
    print(help_text)

def fetch_ip_info(ip):
    """Fetch IP information from ipinfo.io."""
    url = f"https://ipinfo.io/{ip}/json"
    response = requests.get(url).json()
    return {
        "city": response.get("city", "N/A"),
        "region": response.get("region", "N/A"),
        "country": response.get("country", "N/A"),
        "org": response.get("org", "N/A")
    }

def geoip_lookup(ip):
    """Perform a geoip lookup using the external service."""
    url = f"http://test.vo.llnwd.net/geoipquery/?ip={ip}"
    response = requests.get(url).json()
    return {
        "city": response.get("city", "N/A"),
        "country": response.get("country", "N/A"),
        "asn": response.get("asn", "N/A")
    }

def dig_cname(domain, options=None):
    """Perform a dig query to fetch CNAME records."""
    if options is None:
        options = []
    cmd = ['dig'] + options + [domain]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout

def extract_ips(input_text):
    """Extract all unique IPv4 addresses from the input text."""
    return list(set(re.findall(r'\b([0-9]{1,3}\.){3}[0-9]{1,3}\b', input_text)))

def extract_domains(input_text):
    """Extract all unique domain names from the input text."""
    return list(set(re.findall(r'\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b', input_text)))

def main():
    parser = argparse.ArgumentParser(description="Process IPs and domains for geolocation, DNS lookups, etc.")
    parser.add_argument('-f', action='store_true', help='Reformat all IPs in text into a readable list')
    parser.add_argument('-d', action='store_true', help='Dig CNAMEs of all domains in text')
    parser.add_argument('-i', action='store_true', help='Fetch IP info from ipinfo.io')
    parser.add_argument('-h', '--help', action='store_true', help='Display help information')
    
    args = parser.parse_args()

    if args.help:
        display_help()
        return

    input_text = input("Enter text containing IP addresses or CNAMEs (end input with '~' on a new line):\n").strip()
    input_text = input_text.replace("~", "")

    ips = extract_ips(input_text)
    if not ips:
        print("No IP addresses found in the input.")
        return

    if args.f:
        print("Reformatted IP addresses:")
        for ip in ips:
            print(ip)
        return

    if args.i:
        print("Fetching IP info from ipinfo.io:")
        for ip in ips:
            info = fetch_ip_info(ip)
            print(f"{ip}: {info['city']}, {info['region']}, {info['country']} - {info['org']}")
        return

    if args.d:
        domains = extract_domains(input_text)
        print("Performing dig on CNAMEs:")
        for domain in domains:
            print(dig_cname(domain))
        return

    # Perform geoip lookups for all IPs
    for ip in ips:
        geo_info = geoip_lookup(ip)
        print(f"{ip} : {geo_info['city']}, {geo_info['country']} ASN: {geo_info['asn']}")

if __name__ == "__main__":
    main()
