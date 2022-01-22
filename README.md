<h1 align="center">Nmapthon2</h1>

<div align="center">
  <strong>A modern Nmap automation library for Python</strong>
</div>

<br />

<div align="center">
  <h3>
    <a href="https://nmapthon2.readthedocs.io/en/latest/">
      Official Documentation
    </a>
    <span> | </span>
    <a href="https://pypi.org/project/nmapthon2/">
      PyPI
    </a>
  </h3>
</div>

<div align="center">
  <sub> Built with ❤︎ by Christian Barral.
</div>

## Table of Contents
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Example](#example)
- [NSE](#nse)
- [License](#license)

## Features
- __Launch Nmap scans__ both synchronous and asynchronously.
- __Get information:__ from every single scan detail.
- __Extend Nmap's NSE__ with Python functions.
- Automate NSE sciripts __output parsing__.
- Check scan __statuses:__ and save different __output formats__.
<!-- - Register NSE __event hooks__. -->
- Use a set of built-in __utilities__.
- __Cross-platform__ module!
  
## Prerequisites
- Install the latest version from <a href="https://nmap.org/">Nmap</a> on your system
- Make sure you have Python 3.5+
  
## Installation
After installing Nmap, open a terminal or a Powershell and install the library:
```bash
pip install nmapthon2
  
# Or
pip3 install nmapthon2
```

## Example
This is just a little example, check all the features in the <a href="https://nmapthon2.readthedocs.io/en/latest/">official documentation</a>
```python
import nmapthon2 as nm2
  
scanner = nm2.NmapScanner()
result = scanner.scan(['192.168.0.0/24', 'localhost'], ports='1-1024', arguments='-sS -sV')

for host in result:
    print(f'I discovered {host.ipv4}!')
    os = host.most_accurate_os()
    if os:
        print(f'O.S: {os.name}')
    
    for port in host:
        if port.service:
            print(f'  Executed scripts from {port.number}/{port.protocol})')
            for script_name, script_output in port.service.all_scripts():
                print(f'{script_name} - {script_output}')
```

## NSE
Register your own NSE parsers, host scripts and port scripts as Python code. with a single line of code.

```python
import nmapthon2 as nm2

scanner = nm2.NmapScanner()
engine = nm2.NSE()
  
# Example of host script
@engine.host_script('my-host-script')
def my_host_script(host):
    try:
        target = host.hostnames()[0]
    except IndexError:
        target = host.ipv4
    print(f'Launching security check number 1 against {target}')
    
    return 'Vulnerable'
  
@engine.port_script('is-nginx', [80, 443, 8080], proto='tcp')
def my_port_script(host, port, service):
    if service and 'nginx' in service.name.lower():
        return True
    else:
        return False
  
@engine.global_parser
def global_parser_example(output):
    # Remove all HTML-encoded < >
    return output.replace('&lt;', '<').replace('&gt;', '>')
  
result = scanner.scan('localhost', engine=engine)
...
```

## License
[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)
