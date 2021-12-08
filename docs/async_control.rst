Controlling async scans
=======================

A ``NmapAsyncScanner`` instance can be used to run scanners the same way as ``NmapScanner`` does, but since it is asynchronous, it won't return the result directly
from the ``scan()`` method. To be able to control your Nmap process and get the results, you can use the following methods:

- ``finished()``: Returns ``True`` if the scan has finished its execution, ``False`` in any other case.
- ``wait()``: Freezes the calling thread until Nmap has finished its execution.
- ``get_result()``: Returns the ``NmapScanResult`` object from the performed scan.
- ``reset()``: Resets the scanner internal values, read below.

.. important::

    **A word on get_result()**. An ``NmapAsyncScanner`` instance uses several instance attributes and flags to perform internal operations, like 
    passing values around, controlling different arguments, etc... calling the ``get_result()`` method will reset all those flags, and that is because
    it is supposed that the programmer will always be calling this method. If that **is not the case**, you should call the ``reset()`` method yourself 
    before starting the next scan to avoid potential unexpected behaviours.

Example 1
+++++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapAsyncScanner()

    scanner.scan('scanme.nmap.org', ports='1-10000', arguments='-sS -T2 -sV')

    for i in range(1, 4):
        print(f'Doing another task, number {i}')
    
    scanner.wait()
    result = scanner.get_result()

    for host in result:
        # Continue....

Example 2
+++++++++

.. code-block:: python

    import nmapthon2 as nm2

    from other_file import long_repeated_task

    scanner = nm2.NmapAsyncScanner()

    scanner.scan('scanme.nmap.org', ports='1-10000', arguments='-sS -T2 -sV')

    while not scanner.finished():
        long_repeated_task()
    
    result = scanner.get_result()

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.async_.NmapAsyncScanner
    :members: finished, wait, get_result, reset