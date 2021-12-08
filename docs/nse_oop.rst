Object-Oriented registry
========================

One of the coolest things about the ``NSE`` object is that it can be inherited, allowing programmers to create their own engines with an object-oriented approach. 

In order to register methods as scripts or parsers, you will need to use decorators. These decorators are the exact same decorators as the ones in :doc:`nse_flask`, but instead of being called from an NSE instance, you will have to import them separately.

.. code-block:: python

    import nmapthon2 as nm2
    # Do not forget to import the decorators manually
    from nmapthon2.engine import host_script, port_script, parser, global_parser


    class CustomNSE(nm2.NSE):

        def __init__(self):
            super().__init__(self)
            # Add any additional attributes you want
            self.example = 'I am just an attribute used to facilitate programming :('
        
        # Its an instance method, do not forget the 'self' keyword
        @host_script('is-blacklisted', targets='192.168.0.0/24')
        def is_blacklisted_ip(self, host):
            with open('/tmp/blacklist_hosts.txt') as f:
                if host.ipv4 in f.read():
                    return True
            return False
        
        @port_script('smtp-banner', 25, proto='tcp')
        def get_smtp_banner(self, host, port, service):
        s = socket.socket()
        s.connect((host.ipv4, port.number))
        banner = s.recv(1024)
        return banner
    
        @parser('http-git')
        def parse_git_repo(self, output):
            if "Git reposity found" in output:
                return True
            else:
                return False

        @global_parser
        def delete_all_too_many_spaces(self, output):
            return re.sub(' +', ' ', output)
        
        def this_wont_be_registered(self):
            return f'This method will not be registered! {self.example}'
    
    # Do not forget you pass an INSTANCE, not a class
    scanner = nm2.NmapScanner(engine=CustomNSE())

    result = scanner.scan(['localhost', '192.168.0.0/24'], arguments='-sC -T4 -n')
    # All the functions registered into the engine will be executed
    # Continue as normal

Related documentation
+++++++++++++++++++++

.. autoclass:: nmapthon2.engine.host_script

.. autoclass:: nmapthon2.engine.port_script

.. autoclass:: nmapthon2.engine.parser

.. autoclass:: nmapthon2.engine.global_parser

