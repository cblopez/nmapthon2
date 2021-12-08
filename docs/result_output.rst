Output information
==================

If you specify any output format through the ``scan()`` method, you can get that particular output format from your ``NmapScanResult`` object.

- ``get_output(output:str)``: Returns the output associated with a given format, or ``None`` if there is no output from it. Valid values are ``"xml"``, ``"grep"`` or ``"normal"``.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2
    from nmapthon2.ports import tcp, udp

    scanner = nm2.NmapScanner()

    # Note the output kwarg value
    result = scanner.scan('scanme.nmap.org', arguments='-sS -sV -T4', ports=tcp('1-10000').udp('1-100'), output=('xml', 'normal'))

    print(f'Normal output: \n\n{result.get_output("normal")}')

    print(f'XML output: \n\n{result.get_output("xml")}')

    # This returns None
    print(f'Grep output: \n\n{result.get_output("grep")}')

    # This raises ValueError
    print(f'Whatever output: \n\n{result.get_output("whatever")}')


Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.results.NmapScanResult.get_output