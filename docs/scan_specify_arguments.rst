Specify scan arguments
======================

For specifying scan arguments, the ``scan()`` method accepts all the Nmap arguments as a string through the ``arguments=`` parameter. This string 
should contain **any nmap scan arguments besides**:

* Targets, which are specified through the ``targets`` argument.
* Ports, which are specified through the ``ports=`` argument.
* Output options (-oX, -oA, -oN....). See the following sub-section to learn how to store Nmap output.
* The ``--resume`` option. Use ``scanner.resume()`` instead, it is also documented in this section.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    from nmapthon2 import tcp, udp

    scanner = nm2.NmapScanner()

    # This is good
    result = scanner('localhost', arguments='-sT -T4')

    # This is good
    result = scanner('google.com', ports=443, arguments='-sS --script http-title -T2')

    # This is good
    result = scanner('192.168.0.2', ports='1-1000', arguments='-sS -n -sV -O')

    # This is good
    result = scanner('10.10.10.200', ports=tcp('1-10000').udp('1-1000'), arguments='-sS -sU -T4')

    # This is NOT good!
    result = scanner('localhost', ports=25, arguments='-sS google.com')

    # This will raise an NmapScanError
    result = scanner('localhost', arguments='-oX test.xml')

    # This will also raise an NmapScanError
    result = scanner('localhost', arguments='--resume /tmp/scan.xml')