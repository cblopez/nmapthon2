Error handling
==============

If you specify something incorrectly or any special case occur (enumerated below) a custom Nmapthon2 exception may be raised during your  ``scan()`` execution.

* ``nmapthon2.exceptions.InvalidPortError``: If any of your ports is not correctly specified. For example, this could be an out-or-range port like 70000.
* ``nmapthon2.exceptions.InvalidArgumentError``: If any of your arguments is invalid. Particularly, if you specify output options through anything that is not the ``output=`` argument, or use the ``--resume`` option instead of ``resume()``.
* ``nmapthon2.exceptions.NmapScanError``: This error may raise on different situations:
    * If you don't have Nmap installed on the system, or your Nmap binary path is incorrectly set.
    * If the Nmap tool raises an error. Like, for example, you use an invalid argument like '-sZZ'.
    * If no output from Nmap is given.

.. note::

    Both ``InvalidPortError`` and ``InvalidArgumentError`` are subclasses of ``NmapScanError``. Head to the "Errors" section to learn more about this topic.

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner_bad = nm2.NmapScanner(nmap_bin='/whatever')
    scanner_good = nm2.NmapScanner()

    # Raises NmapScanError
    result = scanner_bad.scan('localhost')

    # Raises NmapScanError
    result = scanner_bad.scan('localhost', arguments='-7 -T4 -n')

    # Raises InvalidArgumentError
    result = scanner_good.scan('localhost', arguments='--resume /tmp/nmap.xml')

    # Raises InvalidPortError
    result = scanner_good.scan('localhost', ports=[22, 56, '100-70000'])

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.exceptions.NmapScanError

.. autoclass:: nmapthon2.exceptions.InvalidArgumentError

.. autoclass:: nmapthon2.exceptions.InvalidPortError