from nmapthon2.parser import XMLParser
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports
from nmapthon2.engine import NSE

#result = XMLParser().parse_file('./tests/assets/test.xml')

def test(output):
    return '{}!!!'.format(output)

nse = NSE()
nse.add_parser('http-title', test)
test = NmapScanner(engine=nse)
result = test.scan('localhost', ports=top_ports(1000), arguments='-sS -T5 --script http-title', output='normal')

print(result.get_output('normal'))

for i in result:
    for port in i:
        if port.get_service():
            print(port.get_service()._scripts)