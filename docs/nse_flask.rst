Flask-like registry
===================

In this first example, we will learn how to instantiate the ``NSE`` object and use it to register functions into the scanner by using decorators. To create an ``NSE`` object, simply import it an instantiate it.
It does not require any parameters:

.. code-block:: python

    import nmapthon2 as nm2

    nse = nm2.NSE()

Registering functions
+++++++++++++++++++++

Depending on if we are registeting a host script, a port script, a global parser or an individual parser, we need to use different decorators.

Registering host scripts
************************

Use the ``host_script(custom_script_name)`` method. Optional parameters from this method can be used to filter out what hosts the script should be executed against. See the documentation from this method for more information.

.. code-block:: python

    import socket
    import nmapthon2 as nm2

    # Check the utilities section
    from nmapthon2.utils import dispatch_network

    nse = nm2.NSE()

    # This applies to all targets
    @nse.host_script('socket-hostname')
    def get_hostname(host):

        return socket.gethostbyaddr(host.ipv4)[0]

    # This applies to google.com only.
    @nse.host_script('private-address', targets=['google.com'])
    def is_private_address(host):
        return host.ipv4 in dispatch_network('192.168.0.0/24')

    scanner = NmapScanner(engine=nse)

    # Since engine was specified on NmapScanner instantiation, no need to pass it here
    result = scanner.scan(['localhost', 'google.com'], ports='1-500')

    for host in result:
        print(f'Host: {host.ip}')
        
        for name, output in host.all_scripts():
            print(f'\t{name} - {output}')

Would produce an output similar to:

.. code-block:: 

    Host: 127.0.0.1
        socket-hostname - kubernetes.docker.internal
    Host: 142.250.200.78
        socket-hostname - mad07s24-in-f14.1e100.net
        private-address - False

.. autoclass:: nmapthon2.engine.NSE.host_script