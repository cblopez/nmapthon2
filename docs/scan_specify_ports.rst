Specify scan target ports
=========================

Nmapthon2 presents a new original way for specifying what ports to scan. Such ports are specified through the ``ports=`` parameter from the ``scan()`` method.
Values accepted for setting the target ports are:

* ``int``: Scan a single port
* ``str``: Scan one or more ports in Nmap-like format. This includes port ranges
* ``Iterable``: Pass an iterable object with ports as ``int`` or ``str``.
* Custom functions: Use ``tcp()``, ``udp()`` or ``top_ports()`` to set the ports in a Pythonic way.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2
    
    from nmapthon2.ports import tcp, udp, top_ports # Dont forget to import these functions

    scanner = nm2.NmapScanner()

    # By default, scanned ports will be TCP unless the -sU argument is used (See the next subsection)
    # Scan port 80/tcp
    result = scanner.scan('localhost', ports=80)

    # Scan port 22/tcp
    result = scanner.scan('localhost', ports='22')

    # Scan registered tcp ports
    result = scanner.scan('localhost', ports='1-1024')

    # Scan ports 80/tcp and 443/tcp
    result = scanner.scan('localhost', ports=[80, 443])

    # Scan port 22/tcp and from 50/tcp to 100/tcp
    result = scanner.scan('localhost', ports=[22, '50-100'])

    # Scan registered tcp ports
    result = scanner.scan('localhost', ports=tcp('1-1024'))

     # Scan registered UDP ports. Remember to use -sU
    result = scanner.scan('localhost', ports=udp('1-1024'), arguments='-sU')

    # You can concatenate tcp and udp functions. Remember to specify -sS for TCP and -sU for UDP
    # this equals to -pT:1-10000,U:53,60-100
    result = scanner.scan('localhost', ports=tcp('1-10000').udp([53, '60-100']), arguments='-sS -sU')

    # You can also set --top-ports 1000 (for example), by default TCP 
    result = scanner.scan('localhost', ports=top_ports(1000))

    # You CANNOT concatenate tcp/udp functions with top_ports
    # ERROR
    result = scanner.scan('localhost', ports=top_ports(100).udp(53))
