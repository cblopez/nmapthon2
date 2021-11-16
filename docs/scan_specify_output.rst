Specify scan output types
=========================

One thing that the original Nmap tool can't do is output the results to multiple formats. Yes, you can use the ``-oA`` option to export normal, XML and grep files,
but what happens if you only want two of those? Nmapthon2 allows to specify which output formats should be stored inside the result produced by ``scan()`` through the
``output=`` parameter. Such parameter can have multiple possible values:

* A single output format between ``'all'``, ``'normal'``, ``'xml'`` or ``'grep'``.
* An iterable object with any of the previously mentioned values, besides ``'all'``. (Because, if you want all of them, just type ``'all'`` u fool).

Please head to the <get_output> section to see how to retrieve the different output formats once you get the result from executing the ``scan()`` method.

.. warning:: 

    This functionality, if selected, uses your file system to temprary store all Nmap output files. The folder used to do so is your OS temporal folder, which is
    commonly defined by environment variables. In case Nmapthon2 creates any file, it ensures that all of them will be deleted independently of any errors raising.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    # Save the output as raw XML format
    result = scanner.scan('192.168.0.0/24', output='xml')

    # Save the output as raw greppable and normal formats
    result = scanner.scan('192.168.0.0/24', output=('grep', 'normal'))

    # Save all output types
    result = scanner.scan('192.168.0.0/24', output='all')

    # Who wants the script kiddie output?
    result = scanner.scan('192.168.0.0/24', output='kiddie')