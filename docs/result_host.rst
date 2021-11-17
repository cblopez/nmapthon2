Hosts information
=================

The result returned by the ``scan()`` method, apart from the scan information, it mainly stores scanned hosts information. Each host that responded to the scan
is represented by a ``Host`` instance. Nmapthon2 allows to interact with the ``NmapScanResult`` object in several ways to achieve different effects.

.. code-block:: python

    import nmapthon2 as nm2
    from nmapthon2.ports import top_ports

    scanner = nm2.NmapScanner()

    # Take into account that only hosts that respond will be stored
    result = scanner.scan(['localhost', '192.168.0.0/24'], arguments='-sS -n -T4', ports=top_ports(100))

    # Get a list with all scanned hosts
    hosts = result.scanned_hosts()

    # Directly iterate through the NmapScanResult Object
    for host in result:
        print(f'This is a host instance: {host}')
    
    # Get a host by IPv4. This will return None if the host could not be scanned
    one_host = result['192.168.0.1']

    # Get a host by hostname. This will return None if the host could not be scanned
    another_host = result['localhost']

    # Check if a host has been scanned by IPv4 or hostname
    if 'localhost' in result:
        print('We could scan localhost successfully!')
    
    # You can also create an iterable if necessary
    iterable_results = iter(result)

Inspecting hosts
****************

Each ``Host`` instance holds information from the scanned host. In this examples, we will learn how to retrieve all the available information
from a single host. To learn how to get information from scanned ports, services, operating system, traceroute and scripts please head into the next
sub-sections.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # We will use the test.xml file for this example
    result = scanner.from_file('./tests/assets/test.xml')

    # That file contains results from 172.17.0.2, so technically we could also retrieve that single host like this
    # scanned_host = result['172.17.0.2']
    # But will iterate over the results
    for host in result:
        print(f'Host: {host.ipv4}')
        print(f'\tState: {host.state}')
        print(f'\tReason: {host.reason}')
        print(f'\tReason TTL: {host.reason_ttl}')
        print(f'\tStarted at: {host.start_time}')
        print(f'\tEnded at: {host.end_time}')
        print(f'\tIpv6: {host.ipv6}')
        print(f'\tFingerprint: {host.fingerprint}\n')

        # We can even compare an object against an IPv4, IPv6 or hostname
        if host == '172.17.0.2':
            print('This is the machine i was looking for!')

Produces the following output:

.. code-block:: 

    Host: 172.17.0.2
        State: up
        Reason: arp-response
        Reason TTL: 0
        Started at: 2021-07-20 10:20:45
        Ended at: 2021-07-20 10:20:45
        Ipv6: None
        Fingerprint: None

    This is the machine i was looking for!

Hostnames information
*********************

Hosts also have associated hostnames. Normally, you would only like to enumarate all hostnames, but if you would like to know the
reason why those hostnames were identified, Nmapthon2 can return the data depening on your needs.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # To test this quickly, scan localhost
    result = scanner.scan('localhost', ports='1-10000', arguments='-T5')

    for host in result:
        print(f'Host: {host.ipv4}')
        
        for hostname in host.hostnames():
            print(f'Hostname: {hostname}')
        
        # With type information
        for hostname, hostname_type in host.hostnames(include_type=True):
            print(f'Hostname (f{hostname_type}): {hostname}')

This code may produce something like this:

.. code-block:: 

    Host: 127.0.0.1
    Hostname: localhost
    Hostname: kubernetes.docker.internal
    Hostname (fuser): localhost
    Hostname (fPTR): kubernetes.docker.internal

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.results.Host
    :members: ipv4, ipv6, state, reason, reason_ttl, start_time, end_time, fingerprint, hostnames