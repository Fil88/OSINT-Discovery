import os
import subprocess
import shutil
import time
import argparse
import socket

# Define colors for formatting
class colors:
    BLUE = '\033[1;36m'
    GREEN = '\033[1;32m'
    RED = '\033[1;31m'
    RESET = '\033[0m'

# Function to run Amass
def run_amass(target, output_dir, amass_path):
    print(f"{colors.BLUE}--==[ Running Amass ]==--{colors.RESET}")
    result = subprocess.run([amass_path, 'enum', '-passive', '-d', target, '-o', os.path.join(output_dir, 'amass_output.txt')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"{colors.RED}[-] Error running Amass: {result.stderr.strip()}{colors.RESET}")
    else:
        print(f"{colors.GREEN}[+] Amass completed.{colors.RESET}")

# Function to run Subfinder
def run_subfinder(target, output_dir, subfinder_path):
    print(f"{colors.BLUE}--==[ Running Subfinder ]==--{colors.RESET}")
    result = subprocess.run([subfinder_path, '-d', target, '-t', '10', '-nW', '--silent', '-o', os.path.join(output_dir, 'subfinder_output.txt')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"{colors.RED}[-] Error running Subfinder: {result.stderr.strip()}{colors.RESET}")
    else:
        print(f"{colors.GREEN}[+] Subfinder completed.{colors.RESET}")

# Function to run DNSRecon
def run_dnsrecon(target, output_dir, custom_wordlist, dnsrecon_path):
    print(f"{colors.BLUE}--==[ Running DNSRecon ]==--{colors.RESET}")
    result = subprocess.run([dnsrecon_path, '-d', target, '-D', custom_wordlist, '-t', 'brt', '--xml', os.path.join(output_dir, 'dnsrecon_output.xml')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"{colors.RED}[-] Error running DNSRecon: {result.stderr.strip()}{colors.RESET}")
    else:
        print(f"{colors.GREEN}[+] DNSRecon completed.{colors.RESET}")

# Function to display summary
def display_summary(updated_wordlist, output_dir):
    print(f"\n{colors.BLUE}--==[ Summary ]==--{colors.RESET}")
    try:
        with open(updated_wordlist, 'r') as f:
            identified_domains = sum(1 for _ in f)
        print(f"{colors.GREEN}[+] Number of identified domains: {identified_domains}{colors.RESET}")
    except FileNotFoundError as e:
        print(f"{colors.RED}[-] Error displaying summary: {e}{colors.RESET}")
        
# Function to run PureDNS
def run_puredns(updated_wordlist, output_dir, puredns_path):
    #print(f"{colors.BLUE}--==[ Running PureDNS to resolve valid domains ]==--{colors.RESET}")
    result = subprocess.run([puredns_path, 'resolve', updated_wordlist], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"{colors.RED}[-] Error running PureDNS: {result.stderr.strip()}{colors.RESET}")
    else:
        # Split the output into lines, remove "www." prefix, and remove duplicates
        domains = {domain.replace("www.", "") for domain in result.stdout.splitlines()}
        # Sort the domains alphabetically
        sorted_domains = sorted(domains)
        # Print the number of resolved valid domains
        print(f"{colors.GREEN}[+] Number of resolved valid domains: {len(sorted_domains)}{colors.RESET}")
        # Write the sorted domains to valid_domains.txt
        with open(os.path.join(output_dir, 'valid_domains.txt'), 'w') as f:
            f.write('\n'.join(sorted_domains))
        #print(f"{colors.GREEN}[+] PureDNS completed.{colors.RESET}")
        

# Function to resolve domain to IP addresses
def resolve_domains_to_ip(domains):
    resolved_ips = {}
    for domain in domains:
        try:
            ip_addresses = socket.gethostbyname_ex(domain)[2]
            resolved_ips[domain] = ip_addresses
        except socket.gaierror as e:
            print(f"{colors.RED}[-] Error resolving IP for domain {domain}: {str(e)}{colors.RESET}")
    return resolved_ips

# Function to run httpx
def run_httpx(updated_wordlist, output_dir, httpx_path):
    print(f"{colors.BLUE}--==[ Running httpx for HTTP probing ]==--{colors.RESET}")
    result = subprocess.run([httpx_path, '-l', updated_wordlist, '-title', '-tech-detect', '-status-code', '-o', os.path.join(output_dir, 'valid_domain_httpx.txt')], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    if result.returncode != 0:
        print(f"{colors.RED}[-] Error running httpx: {result.stderr.strip()}{colors.RESET}")
    else:
        print(f"{colors.GREEN}[+] httpx completed.{colors.RESET}")

# Function to compare results and create an updated wordlist
def compare_results(amass_output, subfinder_output, dnsrecon_output, updated_wordlist):
    print(f"{colors.BLUE}--==[ Comparing Amass, Subfinder, DNSRecon results ]==--{colors.RESET}")
    try:
        with open(amass_output, 'r') as f:
            amass_domains = {line.strip() for line in f}
        with open(subfinder_output, 'r') as f:
            subfinder_domains = {line.strip() for line in f}
        with open(dnsrecon_output, 'r') as f:
            dnsrecon_domains = {line.strip().replace('www.', '') for line in f}
        combined_domains = amass_domains.union(subfinder_domains).union(dnsrecon_domains)
        with open(updated_wordlist, 'w') as f:
            f.write('\n'.join(combined_domains))
        print(f"{colors.GREEN}[+] Comparison completed.{colors.RESET}")
    except FileNotFoundError as e:
        print(f"{colors.RED}[-] Error comparing results: {e}{colors.RESET}")

# Function to store results
def store_results(updated_wordlist, output_dir):
    print(f"{colors.BLUE}--==[ Storing scan results ]==--{colors.RESET}")
    try:
        shutil.copy(updated_wordlist, os.path.join(output_dir, 'all_output.txt'))
        print(f"{colors.GREEN}[+] Storage completed.{colors.RESET}")
    except FileNotFoundError as e:
        print(f"{colors.RED}[-] Error storing results: {e}{colors.RESET}")


# Function to find delta domains
def find_delta_domains(previous_domains, current_domains):
    return current_domains - previous_domains if previous_domains else set()

# Main function
def main():
    print(f"{colors.BLUE}--==[ OSINT script to discover company assets ]==--{colors.RESET}")

    parser = argparse.ArgumentParser(description='OSINT script to discover company assets')
    parser.add_argument('-t', '--target', metavar='TARGET_DOMAIN', type=str, help='Target domain', required=True)
    args = parser.parse_args()

    target = args.target
    output_dir = os.path.join(os.getcwd(), 'output', target)
    wordlist_path = os.path.join(os.getcwd(), 'wordlists')
    custom_wordlist = "/opt/test/light-dns-recon2.txt"
    puredns_path = "/root/go/bin/puredns"
    httpx_path = "/root/go/bin/httpx"
    amass_path = "/root/go/bin/amass"
    subfinder_path = "/root/go/bin/subfinder"
    dnsrecon_path = "/usr/bin/dnsrecon"

    os.makedirs(output_dir, exist_ok=True)

    previous_domains = set()
    valid_domains_file = os.path.join(output_dir, 'valid_domains.txt')
    if os.path.exists(valid_domains_file):
        with open(valid_domains_file, 'r') as f:
            previous_domains = {line.strip() for line in f}

    start_time = time.time()

    run_amass(target, output_dir, amass_path)
    run_subfinder(target, output_dir, subfinder_path)
    run_dnsrecon(target, output_dir, custom_wordlist, dnsrecon_path)

    updated_wordlist = os.path.join(output_dir, 'updated_wordlist.txt')
    compare_results(os.path.join(output_dir, 'amass_output.txt'), os.path.join(output_dir, 'subfinder_output.txt'), os.path.join(output_dir, 'dnsrecon_output.xml'), updated_wordlist)
    
    
    run_httpx(updated_wordlist, output_dir, httpx_path)
    
    display_summary(updated_wordlist, output_dir)
    
    run_puredns(updated_wordlist, output_dir, puredns_path)
    store_results(updated_wordlist, output_dir)
    
    

    end_time = time.time()
    elapsed_time = end_time - start_time
    elapsed_minutes = int(elapsed_time / 60)
    print(f"{colors.GREEN}[+] Time needed to complete the scan: {elapsed_minutes} minutes{colors.RESET}")
    print(f"{colors.GREEN}--==[ Script execution completed ]==--{colors.RESET}")

    # Find delta domains
    if previous_domains:
        with open(valid_domains_file, 'r') as f:
            current_domains = {line.strip() for line in f}
        delta_domains = find_delta_domains(previous_domains, current_domains)
        if delta_domains:
            print(f"{colors.GREEN}[+] New domains since last scan ({len(delta_domains)}): {', '.join(delta_domains)}{colors.RESET}")
        else:
            print(f"{colors.GREEN}[+] No new domains found since last scan{colors.RESET}")
    else:
        print(f"{colors.RED}[-] Previous scan data not found. Cannot determine delta domains.{colors.RESET}")

    # Resolve domains to IP addresses
    if os.path.exists(valid_domains_file):
        with open(valid_domains_file, 'r') as f:
            current_domains = [line.strip() for line in f]
        resolved_ips = resolve_domains_to_ip(current_domains)
        with open(os.path.join(output_dir, 'resolved-ip.txt'), 'w') as f:
            for domain, ips in resolved_ips.items():
                f.write(f"{domain}: {', '.join(ips)}\n")
        print(f"{colors.GREEN}[+] Resolved IP addresses saved to resolved-ip.txt{colors.RESET}")

if __name__ == "__main__":
    main()
