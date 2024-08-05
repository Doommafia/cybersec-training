import scapy.all as scapy
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def scan_subnet(ip_range):
    try:
        print(f"Scanning subnet: {ip_range}")
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

        devices = []
        for element in answered_list:
            device = {
                'ip': element[1].psrc,
                'mac': element[1].hwsrc,
                'name': get_device_name(element[1].psrc)
            }
            devices.append(device)
        return devices
    except Exception as e:
        print(f"Error scanning subnet {ip_range}: {e}")
        return []

def get_device_name(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None

def print_devices(devices):
    print("IP Address\t\tMAC Address\t\tDevice Name")
    print("-" * 60)
    for device in devices:
        print(f"{device['ip']}\t\t{device['mac']}\t\t{device['name']}")

if __name__ == "__main__":
    subnets = [f"192.168.{i}.0/24" for i in range(0, 256)]
    all_devices = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_subnet = {executor.submit(scan_subnet, subnet): subnet for subnet in subnets}
        for future in as_completed(future_to_subnet):
            subnet = future_to_subnet[future]
            try:
                devices = future.result()
                all_devices.extend(devices)
            except Exception as e:
                print(f"Error retrieving result for subnet {subnet}: {e}")

    print_devices(all_devices)
