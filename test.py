from nmapthon2.parser import XMLParser
from nmapthon2.scanner import NmapScanner
from nmapthon2.ports import top_ports
from nmapthon2.engine import NSE, host_script, parser


test = NmapScanner()
result = test.scan('localhost 192.168.0.0/24', ports=(22, '50-100'), dry_run=True)