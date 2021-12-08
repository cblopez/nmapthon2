Raw scan
========

You can also execute raw Nmap commands. Raw commands can include everything you would put in a normal command line nmap call, but without any output parameter nor ``--resume`` option.
No "nmap" keyword should be added to the raw command string, though Nmapthon2 will automatically delete it.
Raw scans do **not** accept multi-output parsing, but you can specify an ``NSE`` object to be used either way.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # Good
    result = scanner.raw('-sS -T4 -n google.com scanme.nmap.org 192.168.0.0/24', engine=nm2.NSE())

    # Good but shoud delete "nmap"
    result = scanner.raw('nmap -sS -T4 -n google.com scanme.nmap.org 192.168.0.0/24', engine=nm2.NSE())

    # Bad, no output options are allowed
    result = scanner.raw('-sS -T4 -n -oX /tmp/output.xml google.com scanme.nmap.org 192.168.0.0/24', engine=nm2.NSE())

    # Bad, use the .resume() method
    result = scanner.raw('--resume /tmp/output.xml', engine=nm2.NSE())


Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.scanner.NmapScanner.raw