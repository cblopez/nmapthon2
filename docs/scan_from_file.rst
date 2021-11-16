Import a scan
=============

A scanner may also import an already existing XML file. This XML file should be completed, which means that it should be a final output from an Nmap scan. In case
the XML file was not completed (due to the scan being interrupted), use ``resume()``.

Example
+++++++

.. code-block:: python

    import pathlib
    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.from_file('/tmp/nmap.xml')

    # You can also use pathlib here
    result = scanner.from_file(pahtlib.Path.cwd() / 'nmap.xml')


Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.scanner.NmapScanner.from_file