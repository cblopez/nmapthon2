Services information
====================

Services are bound to ports. In Nmapthon2, it works the same way. All services are encapsulated into their own ``Service`` object instance, which is almost equal to how services were implemented on the preivous version of this library.

To get the service from a given ``Port`` instance, you can use the ``service`` property or the ``get_service()`` method. If no service has been identified for a given port, then both will return a ``None`` value.

.. important::

    Getting services information requires the ``-sV`` or similar (like ``-A``) Nmap parameter

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.scan('192.168.0.0/24', arguments='-sS -sV -T3 -n')

    for host in result:
        for port in host:
            service = port.service
            # or
            # service = port.get_service()

            if service is not None:
                print(f'We have a Service instance for {port.number}/{port.protocol}')

Inspecting services
+++++++++++++++++++

Services have several properties that hold the scanned service information. Services also store port scripts, but that topic is not covered here. Please head to the <sub-section-link> for more information.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # Do not forget the -sV option, or there wont by any service info
    result = scanner.scan('scannme.nmap.org', arguments='-sS -sV')

    for host in result:
        print(f'Host: {host.ip}')
        for port in host:
            print(f'\tPort: {port.number}/{port.protocol}')

            service = port.service
            if service is not None:
                print('\t\tService info')
                print('\t\t-------------')
                print(f'\t\tName: {service.name}')
                print(f'\t\tProduct: {service.product}')
                print(f'\t\tVersion: {service.version}')
                print(f'\t\tExtrainfo: {service.extrainfo}')
                print(f'\t\tTunnel: {service.tunnel}')
                print(f'\t\tMethod: {service.method}')
                print(f'\t\tConfidence: {service.conf}')
                print(f'\t\tCPEs: {",".join(service.cpes) if service.cpes else "No CPEs found"}')
                print(f'\t\tPort: {service.port}') # It also holds a reference to the port number, so you dont neeed to use the Port instance to get it


This code block would print something similar the following output, depending on your scan results:

.. code-block::

    Host: 45.33.32.156
        Port: 21/tcp
                    Service info
                    -------------
                    Name: ftp
                    Product: vsftpd
                    Version: 2.3.4
                    Extrainfo: None
                    Tunnel: None
                    Method: probed
                    Confidence: 10.0
                    CPEs: cpe:/a:vsftpd:vsftpd:2.3.4
                    Port: 21
            Port: 22/tcp
                    Service info
                    -------------
                    Name: ssh
                    Product: OpenSSH
                    Version: 4.7p1 Debian 8ubuntu1
                    Extrainfo: protocol 2.0
                    Tunnel: None
                    Method: probed
                    Confidence: 10.0
                    CPEs: cpe:/a:openbsd:openssh:4.7p1,cpe:/o:linux:linux_kernel
                    Port: 22

        ...

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.elements.Service
    :members: name, product, version, extrainfo, tunnel, method, conf, cpes, port