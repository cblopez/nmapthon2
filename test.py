from nmapthon2.parser import XMLParser
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports

result = XMLParser().parse_file('./tests/assets/test.xml')
#test = NmapScanner()
#result = test.scan('localhost', ports=800, arguments='-sS -T5 -O', output='normal')

for i in result:
    for port in i:
        print('{}/{}'.format(port.number, port.protocol))