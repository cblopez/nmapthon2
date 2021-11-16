Resume a scan
=============

Nmap has the built-in option ``--resume``, which accepts an XML file and continues the scan from the last entry inside the file. Since this options could be 
quite usefull to have, but its usage collides with the overall library design, it has a function to call it directly

Example
+++++++

.. code-block:: python

    import pathlib
    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.resume('/path/to/nmap.xml')

    # You can also use pathlib
    result = scanner.resume(pahtlib.Path.cwd() / 'nmap.xml')

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.scanner.NmapScanner.resume