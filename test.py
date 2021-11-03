from nmapthon2.parser import XMLParser
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports
from nmapthon2.engine import NSE, NSEBlueprint, host_script

#result = XMLParser().parse_file('./tests/assets/test.xml')

class TestNSE(NSEBlueprint):
    
    def __init__(self):
        super().__init__()
    
    @host_script
    def host_script_dns_brute(self, host):
        return host
    
    def port_script_ssh_brute(self, host, port, service):
        return host

test = NmapScanner(engine=TestNSE())
result = test.scan('localhost', ports=top_ports(1000), arguments='-sS -T5 --script http-title', output='normal')

for i in result:
    print(i._scripts)