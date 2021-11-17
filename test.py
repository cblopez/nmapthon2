from nmapthon2.scanner import NmapScanner
from nmapthon2.exceptions import MissingScript
from nmapthon2.engine import NSE
from nmapthon2.utils import dispatch_network

import socket

nse = NSE()

@nse.host_script('socket-hostname', targets='*')
def get_hostname(host):

    return socket.gethostbyaddr(host.ipv4)[0]

@nse.host_script('private-address', targets=['google.com'])
def is_private_address(host):
    return host.ipv4 in dispatch_network('192.168.0.0/24')

scanner = NmapScanner(engine=nse)

result = scanner.scan('localhost google.com', ports='1-500')


for host in result:
    print(f'Host: {host.ip}')
    
    for name, output in host.all_scripts():

        print(f'\t{name} - {output}')