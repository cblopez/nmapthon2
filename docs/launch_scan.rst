Launch a scan
=============

.. toctree::
    :titlesonly:
    :maxdepth: 1

    scan_specify_targets
    scan_specify_ports
    scan_specify_arguments
    scan_specify_output
    scan_additional_options
    scan_raw
    scan_resume
    scan_from_file
    scan_error_handling

Nmapthon2 allows to execute scans through several methods, but note that all of them require a ``NmapScanner`` instance. 
The main method for launching scans is ``scan()``, which can be used to specify targets, ports, arguments and additional parameters. Below there is a quick 
example, but it is recommended to check the following sub-sections to know how to fully customize the Nmap scan.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # The program will stop until the Nmap scan finishes and will return an NmapScanResult object
    result = scanner.scan('localhost')

Related docucmentation
++++++++++++++++++++++

.. autoclass:: nmapthon2.scanner.NmapScanner.scan