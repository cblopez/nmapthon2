Ports information
=================

Ports, similar to hosts, are also stored in their paraticular ``Port`` instances. Ports can be directly retrieved from ``Host`` objects, and the syntax required to 
do so is really similar to the one seen in the previous sub-section.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.scan(['localhost', '10.10.10.0/23'], ports='1-10000', arguments='-sS -T4')

    for host in result:
        
        # You can directly iterate through hosts objects
        for port in host:
            print(f'This is port instance: {port}')

        # Get a list of all scanned ports
        scanned_ports = host.scanned_ports()

        # Get a list of all scanned TCP ports
        scanned_tcp_ports = host.tcp_ports()

        # Get a list of all scanned UDP ports
        scanned_udp_ports = host.udp_ports()

        # Check if a given Port instance is from a particular port number
        for port in scanned_tcp_ports:
            if port == 80:
                print('I finally found an HTTP port!')

        # You can also create an iterable if necessary
        iterable_ports = iter(host)

Inspecting ports
++++++++++++++++

Each ``Port`` instance holds information from a particular port. Check the following example and related documentation to see what information can be retrieved.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.from_file('./tests/assets/test.xml')

    for host in result:
        print(f'Host: {host.ip}')
        for port in host:
            print(f'\tPort: {port.number}/{port.protocol}')
            # Prints 80/tcp for example
            print(f'\tState: {port.state}')
            # Prints either 'open', 'filtered' or 'closed'
            print(f'\tReason: {port.reason}')
            print(f'\tReason TTL: {port.reason_ttl}\n')

This snippet produces an output similar to this one:

.. code-block:: 

    Host: 172.17.0.2
        Port: 21/tcp
        State: open
        Reason: syn-ack
        Reason TTL: 64

        Port: 22/tcp
        State: open
        Reason: syn-ack
        Reason TTL: 64

        Port: 23/tcp
        State: open
        Reason: syn-ack
        Reason TTL: 64

        ... 

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.elements.Port
    :members: number, protocol, state, reason, reason_ttl