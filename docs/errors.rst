Errors
======

This page enumerates and shows the hierarchy from all the custom exceptions created for Nmapthon2. 
All of them are defined inside ``nmapthon2.exceptions``

.. code-block::

    Exception
    |
    |- XMLParsingError
    |- MissingScript
    |- StopExecution
    |- EngineError
    |- NmapScanError
       |- InvalidPortError
       |- MalformedIpAddressError
       |- InvalidArgumentError