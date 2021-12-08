General scan information
========================

The result returned from the ``scan()`` method can be directly used to access overall scan information.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # You can use the text.xml file from this repo to test things.
    # Remember to scan scanme.nmap.org or your virtual machines!
    result = scanner.from_file('./tests/assets/test.xml')

    print(result.scanner)
    # Prints 'nmap'
    print(result.arguments)
    # Prints 'nmap -sS -sV -A --top-ports 200 -oX test.xml -T4 --traceroute 172.17.0.2'
    print(result.start_timestamp)
    # Prints 1626769244
    print(result.start_datetime)
    # Prints 2021-07-20 10:20:44 (datetime.datetime object)
    print(result.end_timestamp)
    # Prints 1626769266
    print(result.end_datetime)
    # Prints 2021-07-20 10:21:06 (datetime.datetime object)
    print(result.version)
    # Prints '7.91'
    print(result.elapsed)
    # Prints 22.06
    print(result.summary)
    # Prints 'Nmap done at Tue Jul 20 10:21:06 2021; 1 IP address (1 host up) scanned in 22.06 seconds'
    print(result.exit_status)
    # Prints 'success'
    print(result.hosts_up)
    # Prints 1
    print(result.hosts_down)
    # Prints 0
    print(result.num_hosts)
    # Prints 1
    print(result.scan_info)
    # Prints {'tcp': {'type': 'syn', 'numservices': '200', 'services': '1,3,7,9,13,17,19,21-23,25-26,37,53,79-82,88,100,106,110-111,113,119,135,139,143-144,179,199,254-255,280,311,389,427,443-445,464-465,497,513-515,543-544,548,554,587,593,625,631,636,646,787,808,873,902,990,993,995,1000,1022,1024-1033,1035-1041,1044,1048-1050,1053-1054,1056,1058-1059,1064-1066,1069,1071,1074,1080,1110,1234,1433,1494,1521,1720,1723,1755,1761,1801,1900,1935,1998,2000-2003,2005,2049,2103,2105,2107,2121,2161,2301,2383,2401,2601,2717,2869,2967,3000-3001,3128,3268,3306,3389,3689-3690,3703,3986,4000-4001,4045,4899,5000-5001,5003,5009,5050-5051,5060,5101,5120,5190,5357,5432,5555,5631,5666,5800,5900-5901,6000-6002,6004,6112,6646,6666,7000,7070,7937-7938,8000,8002,8008-8010,8031,8080-8081,8443,8888,9000-9001,9090,9100,9102,9999-10001,10010,32768,32771,49152-49157,50000'}}
    print(result.verbose)
    # Prints 0
    print(result.debug)
    # Prints 0
    print(result.tolerant_errors)
    # Prints None, but would print a string if there were any.    

    

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.results.NmapScanResult
    :members: scanner, arguments, start_datetime, start_timestamp, end_datetime, end_timestamp, version, elapsed, summary, exit_status, hosts_up, hosts_down, num_hosts, scan_info, verbose, debug, tolerant_errors