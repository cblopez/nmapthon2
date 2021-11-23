from nmapthon2.scanner import NmapScanner
from nmapthon2.exceptions import MissingScript
from nmapthon2.engine import NSE

import requests

nse = NSE()

# This applies to all scripts
@nse.global_parser
def change_html_chars(output):
    return output.replace('&lt;', '<').replace('&gt;', '>')

# This only applies to the built-in http-enum.nse script
# It transforms the script output in a list of found directories.
# If you do this type of data transformation, remember it wont be a string anymore!s
@nse.parser('http-enum')
def get_directories_list(output):
    data = []
    for line in output.splitlines():
        split_line = line.strip().split(':')
        if len(split_line) > 1:
            data.append(split_line[0])
    
    return data

scanner = NmapScanner(engine=nse)

result = scanner.scan('localhost', ports=8000, arguments='-sV -sS -T4 --script http-title,http-enum')

for host in result:
    print(f'Host: {host.ip}')

    for hs_name, hs_output in host.all_scripts():
        print(f'\t{hs_name} - {hs_output}')
    
    print()
    for port in host:
        print(f'\tPort {port.number}/{port.protocol} ({port.state}):')

        if port.service is not None:
            for name, output in port.service.all_scripts():
                print(f'\t\t{name} - {output}')