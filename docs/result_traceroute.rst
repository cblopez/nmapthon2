Traceroute information
======================

Traceroute in Nmapthon2 works exactly the same as it did initially, but the container class name changes a little.
Traceroute information is stored inside a ``Host`` object, and each hop from the traceroute is stored inside a ``Hop`` object.

.. important::
    
    In order to have traceroute information, the ``--traceroute`` Nmap parameter is mandatory.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.scan('scanme.nmap.org', arguments='--traceroute')

    for host in result:

        hop_list = host.traceroute()

Inspecting hops
+++++++++++++++

Each ``Hop`` represents a node that responded with an ICMP packet. For this example, a Docker container has been used, since most intermediate hosts
block ICMP pings nowadays, so using public domains with traceroute would not be very explanatory.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # Host must respond in order to have traceroute info
    result = scanner.scan('172.17.0.2', arguments='--traceroute -Pn -T5', ports='1-100')

    for host in result:
        print(f'Host: {host.ip}')

        for i, hop in enumerate(host.traceroute()):
            print(f'\tHop #{i + 1}')
            print('\t------------')
            print(f'\tHost: {hop.host}')
            print(f'\tIP: {hop.ip}')
            print(f'\tRTT: {hop.rtt}')
            print(f'\tTTL: {hop.ttl}\n')

Would produce an output similar to:

.. code-block:: 

    Host: 172.17.0.2
        Hop #1
        ------------
        Host: None
        IP: 192.168.0.1
        RTT: 0.00
        TTL: 1

        Hop #2
        ------------
        Host: None
        IP: 10.5.0.1
        RTT: 7.00
        TTL: 2

        Hop #3
        ------------
        Host: 50.15.26.77.sanitized.sanitized.com
        IP: 17.__.35.__ # This IP has been sanitized
        RTT: 8.00
        TTL: 3

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.elements.Hop
    :members:
