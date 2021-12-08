Creating a Scanner
==================

With Nmapthon2, you only need to create a single ``NmapScanner`` object and use it any number of times. This object can recieve two optional ``kwargs`` parameters:  

* ``engine: Union[None,NSE] = None``: Specify an ``NSE`` instance to be used as generic engine for any scan made with the instantiated scanner. Please head to  :doc:`nse` to learn more about the ``NSE``.
* ``nmap_bin: Union[None,str] = None``: Set the Nmap binary path, including the name. For example, ``"/tmp/nmap"`` would be a valid path. The default ``None`` value means that it will be taken from the system's $PATH.

Example
+++++++

.. code-block:: python

    # Import the library
    import nmapthon2 as nm2

    # Create a scanner with no engine and using the nmap command inside the $PATH
    scanner = nm2.NmapScanner()

    # Create a scanner with a custom Nmap binary
    scanner = nm2.NmapScanner(nmap_bin=r"C:\Program Files\nmap\nmap.exe")

    # Create a scanner with a default NSE object (ignore if you haven't read about the NSE object)
    scanner = nm2.NmapScanner(engine=nm2.NSE())

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.scanner.NmapScanner