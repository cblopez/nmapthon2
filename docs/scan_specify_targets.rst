Specify scan targets
====================

Targets are the only required parameter to be specified on the ``scan()`` method. These targets can be from several types, including:

* Hostnames
* Domains
* IP addresses
* IP ranges
* IP partial ranges
* IP networks with CIDR masks

The ``targets`` parameter can be either a single ``str`` or an ``Iterable``.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # Scan a single host with an str parameter
    result = scanner.scan('localhost')

    # Scan a single host with a list parameter
    result = scanner.scan(['localhost'])

    # Scan multiple hosts
    result = scanner.scan(['google.com', 'facebook.com'])

    # Scan a network range
    result = scanner.scan('192.168.0.0-192.168.0.10')

    # Scan a network partial range.
    result = scanner.scan('192.168.0-9.1') # Scans 192.168.0.1, 192.168.1.1.... 192.168.9.1
    # You can also use multiple sub-ranges
    result = scanner.scan('10.10.10-12.0-200')

    # Scan a network with CIDR mask
    result = scanner.scan('192.168.0.0/24') # It automatically excludes network and broadcast addresses

    # Mix all the options however you want. Nmapthon2 automatically deletes duplicated targets
    targets = ('localhost', 'facebook.com', '192.168.0.0/24', '192.168.0.0-192.169.254')
    result = scanner.scan(targets)