Utilities
=========

Nmapthon2 comes with a series of utilities that, some of them, are used internally by the library. Nmapthon's first version would use all of these utilities as well,
but they were declared as protected with non intuitive names.

Here is a list of all the functions that can be accessed through ``nmapthon2.utils``:

- ``valid_port(port)``: Check if a given port is within the defined port range (between 1 and 65535, both included).
- ``valid_ip(ip)``: Check if a given string is a valid IPv4.
- ``ports_to_list(ports)``: Transform a string with Nmap-like syntax into a ``list`` of individual ports.
- ``extend_port_list(port_list)``: Transform a list of strings with Nmap-like syntax into a list with individual ports.
- ``ports_to_str(port_list)``: Transform a list of individual ports into a single string with Nmap-like syntax.
- ``ip_range(starting_ip, ending_ip)``: Create a list of individual IPv4s that are between the specified range.
- ``partial_ip_range(partial_ip_expression)``: Transform a partial Nmap-like IPv4 expression into a list of individual IPs.
- ``dispatch_network(network)``: Create a list with all the IPs from a given network with CIDR like "192.168.0.0/24", excluding the network and broadcast addresses.
- ``targets_to_list``: Transform a string with Nmap-like syntax containing the targets into a list of individual targets.


Example
+++++++

.. code-block:: python

    import nmapthon2.utils as nmutils

    print(f'Is 80000 a valid port? {nmutils.valid_port(80000)}\n')

    print(f'Is 10.12.35.222 a valid ip? {nmutils.valid_ip("10.12.35.222")}\n')

    print(f'Transform this to list: "1-10,200,6000-6002" - {nmutils.ports_to_list("1-10,200,6000-6002")}\n')

    print(f'Transform this to list: ["1-10", "22"] - {nmutils.extend_port_list(["1-10", "22"])}\n')

    print(f'Transform to str: [1,2,3,10] - {nmutils.ports_to_str([1,2,3,10])}\n')

    print(f'IPs in range 192.168.0.1-192.168.0.4 - {nmutils.ip_range("192.168.0.1", "192.168.0.4")}\n')

    print(f'IPs in partial range 192.168.1.10-13 - {nmutils.partial_ip_range("192.168.1.10-13")}\n')

    print(f'Dispatch this: 10.10.10.0/29 - {nmutils.dispatch_network("10.10.10.0/29")}\n')

    print(f'Tranform this targets to list: "localhost google.es 192.168.0.0/30" - {nmutils.targets_to_list("localhost google.es 192.168.0.0/30")}')

Will produce the following output:

.. code-block::

    Is 80000 a valid port? False

    Is 10.12.35.222 a valid ip? True

    Transform this to list: "1-10,200,6000-6002" - [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 200, 6000, 6001, 6002]

    Transform this to list: ["1-10", "22"] - [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 22]

    Transform to str: [1,2,3,10] - 1-3,10

    IPs in range 192.168.0.1-192.168.0.4 - ['192.168.0.1', '192.168.0.2', '192.168.0.3', '192.168.0.4']

    IPs in partial range 192.168.1.10-13 - ['192.168.1.10', '192.168.1.11', '192.168.1.12', '192.168.1.13']

    Dispatch this: 10.10.10.0/29 - ['10.10.10.1', '10.10.10.2', '10.10.10.3', '10.10.10.4', '10.10.10.5', '10.10.10.6']

    Tranform this targets to list: "localhost google.es 192.168.0.0/30" - ['192.168.0.2', 'google.es', 'localhost', '192.168.0.1']

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.utils.valid_port

.. autoclass:: nmapthon2.utils.valid_ip

.. autoclass:: nmapthon2.utils.ports_to_list

.. autoclass:: nmapthon2.utils.extend_port_list

.. autoclass:: nmapthon2.utils.ports_to_str

.. autoclass:: nmapthon2.utils.ip_range

.. autoclass:: nmapthon2.utils.partial_ip_range

.. autoclass:: nmapthon2.utils.dispatch_network

.. autoclass:: nmapthon2.utils.targets_to_list