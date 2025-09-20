import scapy.all as scapy
import socket 
import threading
from queue import Queue
import ipaddress

def scan(ip, result_queue):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = broadcast/arp_request
    answer = scapy.srp(packet, timeout=1, verbose=False)[0]

    clients = []
    for client in answer:
        client_info = {'IP': client[1].psrc, 'MAC': client[1].hwsrc}
        try:
            hostname = socket.gethostbyaddr(client_info['IP'])[0]
            client_info['Hostname'] = hostname
        except socket.herror:
            client_info['Hostname'] = 'Unknown'
        clients.append(client_info)
    result_queue.put(clients)

def print_result(result):
    print('IP' + " "*20 + 'MAC' + " "*20 + 'Hostname')
    print('-'*80)
    for client in result:
        print(client['IP'] + '\t\t' + client['MAC'] + '\t\t' + client['Hostname'])

def main(cidr):import socket
import concurrent.futures
import sys

RED = "\033[91m"
GREEN = "\033[92m"
RESET = "\033[0m"

def format_port_results(results):
    formatted_results = "Port Scan Results:\n"
    formatted_results += "{:<8} {:<15} {:<10}\n".format("Port", "Service", "Status")
    formatted_results += '-' * 50 + "\n"
    for port, service, banner, status in sorted(results):
        if status:
            formatted_results += f"{RED}{port:<8} {service:<15} {'Open':<10}{RESET}\n"
            if banner:
                for line in banner.split('\n'):
                    formatted_results += f"{GREEN}{'':<8}{line}{RESET}\n"
    return formatted_results

def get_banner(sock):
    try:
        sock.settimeout(1)
        return sock.recv(1024).decode().strip()
    except:
        return ""

def scan_port(target_ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target_ip, port))
        if result == 0:
            try:
                service = socket.getservbyport(port, 'tcp')
            except:
                service = 'Unknown'
            banner = get_banner(sock)
            return port, service, banner, True
        else:
            return port, "", "", False
    except:
        return port, "", "", False
    finally:
        sock.close()

def port_scan(target_host, start_port, end_port):
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"{RED}Error: Unable to resolve host '{target_host}'{RESET}")
        return

    print(f"Starting scan on host: {target_ip}")
    results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=400) as executor:
        futures = {executor.submit(scan_port, target_ip, port): port for port in range(start_port, end_port + 1)}
        total_ports = end_port - start_port + 1
        for i, future in enumerate(concurrent.futures.as_completed(futures), start=1):
            port, service, banner, status = future.result()
            results.append((port, service, banner, status))
            sys.stdout.write(f"\rProgress: {i}/{total_ports} ports scanned")
            sys.stdout.flush()

    sys.stdout.write("\n")
    print(format_port_results(results))

if __name__ == '__main__':
    target_host = input("Enter target IP or hostname: ").strip()
    try:
        start_port = int(input("Enter the start port: "))
        end_port = int(input("Enter the end port: "))
        if start_port < 0 or end_port > 65535 or start_port > end_port:
            raise ValueError
    except ValueError:
        print(f"{RED}Invalid port range. Please enter ports between 0 and 65535.{RESET}")
    else:
        port_scan(target_host, start_port, end_port)

    results_queue = Queue()
    threads = []
    network = ipaddress.ip_network(cidr, strict=False)

    for ip in network.hosts():
        thread = threading.Thread(target=scan, args=(str(ip), results_queue))
        thread.start()
        threads.append(thread)
    
    for thread in threads:
        thread.join()
    
    all_clients = []
    while not results_queue.empty():
        all_clients.extend(results_queue.get())
    
    print_result(all_clients)

if __name__ == '__main__':
    cidr = input("Enter network ip address: ")
    main(cidr)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       
