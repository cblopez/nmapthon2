from nmapthon2.parser import XMLParser
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports
from nmapthon2.engine import NSE, host_script, parser


test = NmapScanner()
result = test.scan('localhost', arguments='-7 -T4 -n')
print(result)