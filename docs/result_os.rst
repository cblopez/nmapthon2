Operating system information
============================

Hosts hold information from the operating system, or operating system guesses, made by Nmap. ``Host`` objects can be directly used to get such information. Each operating system match
is stored inside an ``OperatingSystem`` instance, and at the same time, such instances will hold every single Operating System match made by Nmap inside ``OperatingSystemMatch`` instances. The two
``Host`` instance methods that can be used are:

* ``os_matches()``: Returns a list of ``OperatingSystem`` objects.
* ``most_accurate_os()``: Returns the ``OperatingSystem`` that holds the most accurate match. Will return ``None`` in case no operating system could be found.

.. important::

    Getting OS information requires the ``-O`` or similar (like ``-A``) Nmap parameter

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = nm2.NmapScanner('192.168.0.1-200', arguments='-sS -O -T4')

    for host in result:
        print(f'Host: {host.ip}')

        os_matches_list = host.os_matches()

        most_accurate = host.most_accurate_os()

Inspecting Operating Systems
++++++++++++++++++++++++++++

You can use this ``OperatingSystem`` objects to gather all the information reported by Nmap

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.scan('10.10.1.0/24', arguments='-sS -O -Pn -T4 -n')

    for host in result:
        print(f'Host: {host.ip}')

        for i, os_info in enumerate(host.os_matches()):

            print('\tOS Info:')
            print(f'\tMatch #{i + 1}')
            print('\t---------')
            print(f'\tOS: {os_info.name}')
            print(f'\tAccuracy: {os_info.accuracy}')
            print('\tMatches info:\n')

            for j, match in enumerate(os_info.get_matches()):
                print(f'\t\tOS Match Info #{j + 1}:')
                print('\t\t----------------------')
                print(f'\t\tType: {match.type}')
                print(f'\t\tVendor: {match.vendor}')
                print(f'\t\tFamily: {match.family}')
                print(f'\t\tCPE: {match.cpe}\n')

Produces an output similar to the following block, depending your the host's respones.

.. code-block::

    Host: 10.10.1.24
        OS Info:
        Match #1
        ---------
        OS: Linux 4.15 - 5.6
        Accuracy: 100.0
        Matches info:

                OS Match Info #1:
                ----------------------
                Type: general purpose
                Vendor: Linux
                Family: Linux
                Generation: 4.X
                CPE: cpe:/o:linux:linux_kernel:4

                OS Match Info #2:
                ----------------------
                Type: general purpose
                Vendor: Linux
                Family: Linux
                Generation: 5.X
                CPE: cpe:/o:linux:linux_kernel:5
    
    .....


Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.elements.OperatingSystem
    :members:

.. autoclass:: nmapthon2.elements.OperatingSystemMatch
    :members: