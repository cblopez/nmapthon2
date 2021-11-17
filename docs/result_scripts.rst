Scripts information
===================

Nmap has its built-in NSE (Nmap Scripting Engine), which allows users to write .nse files that will execute against the targets.
NSE scripts can be of two types:

* **Host scripts**: Scripts that are executed against the host itself, without taking into account any port nor service. Nmapthon2 saves these scripts under the ``Host`` instances.
* **Port scripts**: Scripts that are port-oriented, which means that they need a specific port to be opened. Nmapthon2 stores these scripts under their related ``Service`` instances.

Both the ``Host`` and the ``Service`` class provide two methods to retrieve NSE scripts names and outputs.

* ``get_script(script_name)``: Returns the script output from a given script name.
* ``all_scripts()``: Returns a list with tuples containing the script name and the script output.

.. important::

    One of the problems with the first version of Nmapthon was scripts output. Nmap would always return a string as a script output,
    but the custom ``NSE`` object does not have to do it, since the programmer may want to return a ``None`` value or raise a ``KeyError``, which 
    may be shadowed depending on the ``get_script()`` implementation. For this purpose, the ``get_script()`` method will raise a custom Exception 
    in case the script does not exist on the host or service: ``nmapthon2.exceptions.MissingScript``. See the example below.

.. note:: 

    Scripts output created from Nmapthon2 custom ``NSE`` are also retrieved the same way. You will see this methods as well when you reach the NSE section.

Inspecting scripts
++++++++++++++++++

The following code block reads all the host-scripts and port-scripts from all the scanned hosts. Note that, for this particualr example ``http-title`` and ``ssh-hostkey`` are port scripts, and ``asn-query`` is a host script. 

.. code-block:: python

    import nmapthon2 as nm2

    scanner = nm2.NmapScanner()

    result = scanner.scan('scanme.nmap.org', ports='1-100', arguments='-sC --script asn-query -sS')

    def format_output(output):
        """ It helps getting one-line outputs. Check the NSE section to see how to automate this
        """
        return ' '.join([x.strip() for x in output.splitlines()])

    for host in result:
        print(f'Host: {host.ip}')
        print(f'\tHost scripts:')
        for name, output in host.all_scripts():
            print(f'\t\t{name} - {format_output(output)}')

        for port in host:
            if port.service and len(port.service.all_scripts()):
                print(f'\tPort scripts ({port.number}/{port.protocol}):')

                for name, output in port.service.all_scripts():
                    print(f'\t\t{name} - {format_output(output)}')

This produces an output similar to the following block.

.. code-block::

    Host: 45.33.32.156
        Host scripts:
                asn-query - No Answers
        Port scripts (22/tcp):
                ssh-hostkey -  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA) 2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA) 256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA) 256 33:fa:91:0f:e0:e1:7b:1f:6d:05:a2:b0:f1:54:41:56 (ED25519)
        Port scripts (80/tcp):
                http-title - Go ahead and ScanMe!

Error handling example
++++++++++++++++++++++

Here is an example of how to control if scripts have worked for a particular host or port.

.. code-block:: python

    import nmapthon2 as nm2
    from nmapthon2.exceptions import MissingScript

    scanner = nm2.NmapScanner()

    result = scanner.scan('localhost', ports='1-100', arguments='-sC --script asn-query -sS')

    for host in result:
        print(f'Host: {host.ip}')

        # This also works with port.service.get_script()
        try:
            print(f'ASN Query: {host.get_script("asn-query")}')
        except MissingScript:
            print(f'ASN Query: Could not be executed')

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.elements.Host
    :members: get_script, all_scripts
    :noindex:

.. autoclass:: nmapthon2.elements.Service
    :members: get_script, all_scripts
    :noindex: