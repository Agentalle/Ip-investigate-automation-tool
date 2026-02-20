import time
import requests

# Function to scan an IP address

def scan_ip(ip):
    # Example processing time
    time.sleep(1)
    # Simulated scanning process
    response = requests.get(f"http://ip-api.com/json/{ip}")
    return response.json()

# Function to scan a list of IP addresses

def scan_ips(ip_list):
    total_ips = len(ip_list)
    for index, ip in enumerate(ip_list):
        result = scan_ip(ip)
        print(f"Scanning {ip}: {result}")  # Stream result for each IP scanned
        print(f"Progress: {index + 1}/{total_ips} IPs scanned.")  # Display progress

if __name__ == '__main__':
    ips_to_scan = ['192.168.1.1', '8.8.8.8', '127.0.0.1']  # Example list of IPs
    scan_ips(ips_to_scan)
