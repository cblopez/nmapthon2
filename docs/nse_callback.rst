Callback registry
+++++++++++++++++

You can also register functions into the ``NSE`` instance by using specific methods to do so. These methods act the same way as decorators in terms of parameters, so they will have the same required and optional parameters, plus the function callback,
to register the function callbacks and apply any needed filtering (for example, select the protocol and states from a port to decide if the script should be applied or not). These functions are:

- ``add_host_script(callback: Callable, name: str)``: Register a function as a host script with a given name.
- ``add_port_script(callback: Callable, name: str, port: Union[int,str,Iterable])``: Register a function as port script with a given name for a set of ports.
- ``add_parser(callback: Callable, name: str)``: Register a function as a parser for a given script.
- ``add_global_parser(callback: Callable)``: Register a function as a global parser.

Example
=======

For this example, we will have two separate files:

.. code-block:: python

    # This is the other_file.py
    # Note that these are example functions, not designed to be quick, just illustrative

    import socket
    import re

    # Host script example
    def is_blacklisted_ip(host):
        with open('/tmp/blacklist_hosts.txt') as f:
            if host.ipv4 in f.read():
                return True
        return False
    
    # Port script example
    def get_smtp_banner(host, port, service):
        s = socket.socket()
        s.connect((host.ipv4, port.number))
        banner = s.recv(1024)
        return banner
    
    # Local parser
    def parse_git_repo(output):
        if "Git reposity found" in output:
            return True
        else:
            return False

    # Global parser
    def delete_all_double_spaces(output):
        return re.sub(' +', ' ', output)

Now the Nmapthon2 file:

.. code-block:: python

    # This could be the main.py
    import nmapthon2 as nm2
    from other_file import is_blacklisted_ip, get_smtp_banner, parse_git_repo, delete_all_double_spaces

    engine = nm2.NSE()

    # Add the host script
    engine.add_host_script(is_blacklisted_ip, 'is-blacklisted', targets='192.168.0.0/24')
    # Add the port script
    engine.add_port_script(get_smtp_banner, 'smtp-banner', 25, proto='tcp')
    # Add the parser for the http-git NSE script
    engine.add_parser(parse_git_repo, 'http-git')
    # Add the global parser
    engine.add_global_parser(delete_all_double_spaces)

    scanner = nm2.NmapScanner()

    result = scanner.scan(['localhost', '192.168.0.0/24'], arguments='-sC -T4 -n', engine=engine)
    # All the functions registered into the engine will be executed
    # Continue as normal
    ...

Related documentation
=====================

.. autoclass:: nmapthon2.engine.NSE.add_host_script

.. autoclass:: nmapthon2.engine.NSE.add_port_script

.. autoclass:: nmapthon2.engine.NSE.add_parser

.. autoclass:: nmapthon2.engine.NSE.add_global_parser

