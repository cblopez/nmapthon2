Retrieving status
=================

You can get Nmap's status from an async scan while its executing:

- ``get_status()``: Return a ``Status`` instance with the information from the current status.

Note that retrieving the status can only be done if you use the ``scan()`` method, all the other methods like ``raw()`` or ``resume()`` will not allow these operations.
Also, you must set the ``with_status=True`` kwarg on the ``scan()`` method to let Nmapthon2 know that you will want to retrieve Nmap's status. You are also able to 
modify the status update interval with ``status_interval='3s'`` kwarg. This kwarg accepts a valid Nmap-like syntax to be placed in front of ``--stats-every``.

.. important::

    It is important to know how status retrieval works on Nmapthon2. To achieve this, Nmapthon2 basically reads the process' STDOUT or output file in chuncks of 256 bytes. 
    **What does this mean?** It means that the ``get_status()`` method is **semi-blocking**, meaning that the program will freeze until it can read 256 bytes from STDOUT. This is not 
    a big deal, since it may only freeze the thread 2-3 seconds at most when running with the default values ('3s'), but note that increasing this ``status_interval`` value would make 
    your ``get_status()`` calls "more blocking". This **does not happen** when specifying the ``output`` parameter, since Nmapthon2 will directly read from the XML output file, rather tham
    STDOUT, which will make it a **non blocking** operation.

.. note::

    Why do you need to specify that you will want to retrieve the status? It is not because I wanted to annoy the programmers, it is because retrieving the status
    will leave a trace of status information inside Nmap's output, so programmers should decide if they want that output to be hidden if they are not really going to 
    get the status inside their code. Of course, they can also perform any post-scan processing to remove that task statuses.

The ``Status`` instance
+++++++++++++++++++++++

A ``Status`` instance has several properties that hold the information from Nmap's status.

- ``task``: Name of the task that is being performed.
- ``time``: ``datetime`` object representing the time from when the status was retrieved.
- ``percent``: ``float`` value that represents the completion percentage from the current task.
- ``remaining``: Number of hosts remaining as an ``int``.
- ``etc``: "Estimated Time of Completion", which is a ``datetime`` object representing the average time when Nmap thinks the task will be completed.

Normally, the ``task``, ``time`` and ``percent`` properties are always present, but any of them will return ``None`` if they could not be extracted from Nmap's output

Example
+++++++

.. code-block:: python

    import nmapthon2 as nm2
    import time

    scanner = NmapAsyncScanner()

    # We even lower the status to 2 seconds
    scanner.scan('localhost', arguments='-sS -p1-20000', with_status=True, output='all', status_interval='2s')

    while not scanner.finished():
        status = scanner.get_status()
        if status:
            print(f'Task: {status.task}. Time: {status.time}. Percent: {status.percent}. Remaining hosts: {status.remaining}. ETC: {status.etc}')
        else:
            print('No status yet')
        time.sleep(1)


    result = scanner.get_result()

May print something like:

.. code-block::

    No status yet
    No status yet
    Task: SYN Stealth Scan. Time: 2021-12-08 19:46:12. Percent: 42.59. Remaining hosts: None. ETC: None

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.status.Status
    :members:

.. autoclass:: nmapthon2.async_.NmapAsyncScanner
    :noindex:
    :members: get_status