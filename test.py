from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports
from nmapthon2.engine import NSE

import requests

nse = NSE()

@nse.port_script('is-nginx', [80,443,8080], proto='tcp')
def is_nginx(host, port, _):
    s = socket.socket()
    s.connect((host.ipv4, port.number))
    banner = s.recv(1024)
    return 'nginx' in banner.decode('utf8')

@nse.port_script('vsftpd-backdoor', 21, proto='tcp', states=['open', 'filtered'])
def check_vsftpd_backdoor(host, port, service):
    return service.product == 'vsftpd' and service.version == '2.3.4' 

scanner = NmapScanner()

result = scanner.scan('localhost google.com', ports=top_ports(100), engine=nse)

for host in result:
    print(f'Host: {host.ip}')
    for port in host:
        if len(port.all_scripts()):
            print(f'\tPort: {port.number}')
            for name, output in port.all_scripts():
                print(f'\t\t{name}: {output}')
