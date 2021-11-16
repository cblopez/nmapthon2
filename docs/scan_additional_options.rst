Specify additional options
==========================

There are other two additional parameters that can me specified inside the ``scan()`` method, which are:

* ``dry_run``: Which accepts a boolean value. If true, it does not execute the Nmap scan, but only initial checks. Really usefull if you want to check if your ``scan()`` arguments are well-written and correctly specifed.
*  ``engine``: ``NSE`` object to use in this particular scan. It overrides the instance's engine, if set. Please head to the <NSE section> for more information. 

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner(engine=nm2.NSE())

    # This returns None and does not raise any error if all the parameters are correct
    result = scanner.scan('localhost', ports='1-1000', arguments='-sT -T5 --min-paralellism 5', dry_run=True)

    # Overrides the initial NSE instance for this scan
    # Still recommended to check the NSE section
    new_engine = nm2.NSE()
    result = scanner.scan('localhost', engine=new_engine)