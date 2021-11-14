from nmapthon2.parser import XMLParser
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports
from nmapthon2.engine import NSE, host_script, parser


class TestNSE(NSE):
    
    def __init__(self):
        super().__init__()
    
    @host_script('localhost')
    def host_script_dns_brute(self, host):
        return host
    
    @parser('http-title')
    def port_script_ssh_brute(self, output):
        return output

test = NmapScanner(engine=TestNSE())
result = test.scan('localhost', ports=top_ports(1000), arguments='-sS -T5 --script http-title', output='normal')

for i in result:
    print(i._scripts)