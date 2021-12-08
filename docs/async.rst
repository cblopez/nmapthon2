Async Scanning
==============

.. toctree::
    :titlesonly:
    :maxdepth: 1

    async_control
    async_status

Nmapthon2 provides another scanner class to perform asynchronous scans and operations, which is ``NmapAsyncScanner``. This class inherits from ``NmapScanner``, so
all the methods that you just learned from the previous sections can also be used here. This class, allows us to:

- Perform scans in the background.
- Pause your main thread until the scan finishes.
- Retrieve the scan status.

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapAsyncScanner()


Documentation
+++++++++++++

.. autoclass:: nmapthon2.async_.NmapAsyncScanner
    :noindex: