from nmapthon2.parser import XMLParser
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports

# result = XMLParser().parse_file('./test.xml')
test = NmapScanner()
result = test.scan('localhost 192.168.0.67', ports=800, arguments='-sS -T5', output='grep')

print(result.get_output('normal'))