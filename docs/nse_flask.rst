Flask-like registry
===================

In this first example, we will learn how to instantiate the ``NSE`` object and use it to register functions into the scanner by using decorators. To create an ``NSE`` object, simply import it an instantiate it.
It does not require any parameters:

.. code-block:: python

    import nmapthon2 as nm2

    nse = nm2.NSE()

Registering functions
+++++++++++++++++++++

Depending on if we are registeting a host script, a port script, a global parser or an individual parser, we need to use different decorators.

Registering host scripts
************************

Use the ``host_script(custom_script_name)`` method. Optional parameters from this method can be used to filter out what hosts the script should be executed against. See the documentation from this method for more information.

.. code-block:: python

    import socket
    import nmapthon2 as nm2

    # Check the utilities section
    from nmapthon2.utils import dispatch_network

    nse = nm2.NSE()

    # This applies to all targets
    @nse.host_script('socket-hostname')
    def get_hostname(host):

        return socket.gethostbyaddr(host.ipv4)[0]

    # This applies to google.com only.
    @nse.host_script('private-address', targets=['google.com'])
    def is_private_address(host):
        return host.ipv4 in dispatch_network('192.168.0.0/24')

    scanner = NmapScanner(engine=nse)

    # Since engine was specified on NmapScanner instantiation, no need to pass it here
    result = scanner.scan(['localhost', 'google.com'], ports='1-500')

    for host in result:
        print(f'Host: {host.ip}')
        
        for name, output in host.all_scripts():
            print(f'\t{name} - {output}')

Would produce an output similar to:

.. code-block:: 

    Host: 127.0.0.1
        socket-hostname - kubernetes.docker.internal
    Host: 142.250.200.78
        socket-hostname - mad07s24-in-f14.1e100.net
        private-address - False

.. autoclass:: nmapthon2.engine.NSE.host_script

Registering port scripts
************************

Use the ``port_script(custom_script_name, ports)`` method. Optional parameters from this method can be used to filter out what hosts and ports the script should be executed against. See the documentation from this method for more information.

.. code-block:: python
    
    import nmapthon2 as nm2

    nse = nm2.NSE()

    # Simple example
    @nse.port_script('is-nginx', [80,443,8080] , proto='tcp', states=['open', 'filtered'])
    def is_nginx(host, port, service):
        
        return service.product is not None and 'is-nginx' in service.product

    # More elaborated example, yet simple
    # Instead of using the decorator to filter out ports, use the function arguments to be more precise, if needed
    @nse.port_script('has-admin-endpoint', '*')
    def has_admin_endpoint(host, port, service):
        # Check if HTTP
        # Always check if attributes are not None to avoid TypeErrors
        if service and service.name and 'http' in service.name:
            if 'https' in service.name or (service.tunnel and 'ssl' in service.tunnel):
                schema = 'https'
            else:
                schema = 'http'
            
            # Call by hostname in case it has one
            if len(host.hostnames()):
                target = host.hostnames()[0]
            else:
                target = host.ipv4

            # Should handle exceptions, timeouts... skipped to make the example easier
            response = resquest.get(f'{schema}://{target}:{port.number}/admin')

            return response.status == 200

    scanner = nm2.NmapScanner(engine=nse)
    result = scanner.scan('some.webserver.org', ports=[80,443,8080,8000], arguments='-sV -sS')

    for host in result:
        print(f'Host: {host.ip}')
        
        for port in host:
            print(f'\tPort {port.number}/{port.protocol} ({port.state}):')

            if port.service is not None:
                for name, output in port.service.all_scripts():
                    print(f'\t\t{name} - {output}')

Could produce an output similar to:

.. code-block::

    Host: 45.33.32.156
        Port 80/tcp (filtered):
            is-nginx - False
        Port 443/tcp (open):
            is-nginx - True
            has-admin-endpoint - True
        Port 8000/tcp (filtered):
        Port 8080/tcp (closed):

.. autoclass:: nmapthon2.engine.NSE.port_script

Registering individual/global parsers
*************************************

A parser is a callback function that is executed to parse any built-in NSE output. Individual parsers are only applied to a particular script, while global 
parsers are applied to all of them. You can use the ``parser(script_name)`` and ``global_parser`` methods to register individual and global parser, respectively.

.. code-block:: python

    import nmapthon2 as nm2

    nse = nm2.NSE()

    # This applies to all scripts
    @nse.global_parser
    def change_html_chars(output):
        return output.replace('&lt;', '<').replace('&gt;', '>')

    # This only applies to the built-in http-enum.nse script
    # It transforms the script output to a list of found directories.
    # If you do this type of data transformation, remember it wont be a string anymore!s
    @nse.parser('http-enum')
    def get_directories_list(output):
        data = []
        for line in output.splitlines():
            split_line = line.strip().split(':')
            if len(split_line) > 1:
                data.append(split_line[0])
        
        return data

    scanner = nm2.NmapScanner(engine=nse)

    result = scanner.scan('localhost', ports=8000, arguments='-sV -sS -T4 --script http-title,http-enum')

    for host in result:
        print(f'Host: {host.ip}')
        for port in host:
            print(f'\tPort {port.number}/{port.protocol} ({port.state}):')

            if port.service is not None:
                for name, output in port.service.all_scripts():
                    print(f'\t\t{name} - {output}')

Can produce an output similar to:

.. code-block:: 

    Host: 127.0.0.1
        Port 8000/tcp (open):
            ... some other scripts output that were called because of http-enum ...
            http-title - This should not be HTML-encoded: <>
            http-enum - ['/error/', '/upload/']

.. autoclass:: nmapthon2.engine.NSE.parser

.. autoclass:: nmapthon2.engine.NSE.global_parser


