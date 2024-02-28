from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_STREAM
from concurrent.futures import ThreadPoolExecutor, as_completed
from ipaddress import ip_network

WELL_KNOWN_PORTS = {
    20: 'FTP (File Transfer Protocol)',
    21: 'FTP (File Transfer Protocol)',
    22: 'SSH (Secure Shell)',
    23: 'Telnet',
    25: 'SMTP (Simple Mail Transfer Protocol)',
    53: 'DNS (Domain Name System)',
    80: 'HTTP (Hypertext Transfer Protocol)',
    110: 'POP3 (Post Office Protocol version 3)',
    143: 'IMAP (Internet Message Access Protocol)',
    443: 'HTTPS (HTTP Secure)',
    3306: 'MySQL',
    3389: 'Remote Desktop Protocol (RDP)',
}


class PortScanner:
    def __init__(self, target, ports, verbose=False):
        self.target = target
        self.ports = ports
        self.verbose = verbose
        self.any_open = False

    def scan_port(self, port):
        try:
            with socket(AF_INET, SOCK_STREAM) as s:
                s.settimeout(1)
                result = s.connect_ex((self.target, port))
                if not result:
                    self.any_open = True
                    service = WELL_KNOWN_PORTS.get(port, 'Unknown')
                    print(f'Port {port} ({service}) is open')
                elif self.verbose:
                    print(f'Port {port} is closed')
        except Exception as e:
            if self.verbose:
                print(f'Error scanning port {port}: {e}')

    def scan_host(self, ip):
        for port in self.ports:
            self.scan_port(port)

    def scan(self):
        if '/' in self.target:
            network = ip_network(self.target, strict=False)
            print(f'Scanning ports {self.ports} on network {network}...')
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(self.scan_host, str(ip)) for ip in network.hosts()]
                for future in as_completed(futures):
                    future.result()
        else:
            print(f'Scanning ports {self.ports} on host {self.target}...')
            self.scan_host(self.target)

    @staticmethod
    def run(target, port_range, verbose=False):
        start_port, end_port = map(int, port_range.split('-'))
        ports = range(start_port, end_port + 1)

        scanner = PortScanner(target, ports, verbose)
        scanner.scan()
        if not scanner.any_open:
            print(f'No open ports found on {target}')


if __name__ == '__main__':
    parser = ArgumentParser(description='TCP Port Scanner')
    parser.add_argument('target', help='Target host or network to scan')
    parser.add_argument('-p', '--ports', metavar='PORTS', help='Port range to scan (e.g., 1-100)', default='1-1024')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    args = parser.parse_args()

    PortScanner.run(args.target, args.ports, args.verbose)
