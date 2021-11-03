#!/usr/bin/env python

# Copyright (c) 2019 Christian Barral

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NON INFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import re

from typing import Iterable, Union, Callable

from .utils import targets_to_list, ports_to_list, extend_port_list
from .exceptions import EngineError, StopExecution
from .elements import Host, Port, Service


_CAMMEL_CASE_SUBSTITUTION_REGEX = re.compile(r'(?<!^)(?=[A-Z])')


def host_script(f):
    """ Decorator to be used from a class inheriting NSE, that automatically adds the decorated function as 
        an NSE host script with the function name in snake case separated by dashes.
        
        :param targets: Targets that may be affected by the script
        :returns: Funciton decorator
    """
    def _host_script_wrapper(self, *args):
        print('Is executing')
        self.add_host_script(f, 'hi', targets)
        return f
    return _host_script_wrapper


class _NSEHostScript:
    """ An individual Python function that is executed as if it were an Nmap NSE host script.
    The script is represented by a name, a function to execute per alive host and the arguments to the function.
        :param name: Name of the function (PyNSEScript name)
        :param func: Function to execute
        :param args: Arguments for the function
        :type name: str
        :type func: function
        :type args: list, tuple
    """

    __slots__ = ('_name', '_func', '_targets')

    def __init__(self, name: str, func: Callable, targets: Union[str, Iterable]):
        self.name = name
        self.func = func
        self.targets = targets

    @property
    def name(self):
        return self._name

    @property
    def func(self):
        return self._func

    @property
    def targets(self):
        return self._targets

    @name.setter
    def name(self, v):
        self._name = v

    @func.setter
    def func(self, v):
        if not callable(v):
            raise EngineError('Function parameter is not callable: {}'.format(v))

        self._func = v

    @targets.setter
    def targets(self, v):
        if isinstance(v, list):
            new_list = []
            for i in v:
                new_list.extend(targets_to_list(i))
            self._targets = list(new_list)
        elif isinstance(v, str):
            if v.strip() == '*':
                self._targets = v
            else:
                self._targets = targets_to_list(v)
        else:
            raise EngineError('Invalid targets data type: {}'.format(type(v)))


class _NSEPortScript(_NSEHostScript):
    """ Represents an NSE port script
    As well as those scripts, it can have any number of arguments and it can assign output to the NmapScanResult object.
    The functions are only executed if the port or host (depending on the function type) is open,
    but the user can also specify which of the three port states ('open', 'filtered'or 'closed') are valid for the
    function to execute.
        :param ports: Port or ports to target. A None value means it is a host script
        :param proto: Transport layer protocol ('tcp', 'udp' or '*' for both)
        :param states: List of states valid for function execution
    """

    __slots__ = ('_ports', '_proto', '_states')

    def __init__(self, name: str, func: Callable, targets: Union[str,Iterable], ports: Union[int,str,Iterable], proto: str, states: Union[str,Iterable]):
        super().__init__(name, func, targets)
        self.ports = ports
        self.proto = proto
        self.states = states

    @property
    def ports(self):
        return self._ports

    @property
    def proto(self):
        return self._proto

    @property
    def states(self):
        return self._states

    @ports.setter
    def ports(self, v):
        if v is None:
            self._ports = v
        elif isinstance(v, str):
            self._ports = ports_to_list(v)

        elif isinstance(v, list):
            self._ports = extend_port_list(v)

        elif isinstance(v, int):
            self._ports = ports_to_list(str(v))

        else:
            raise EngineError('Invalid ports data type: {}'.format(type(v)))

    @proto.setter
    def proto(self, v):
        if v is None:
            self._proto = None
        elif isinstance(v, str) and v.lower() in ['tcp', 'udp', '*']:
            self._proto = v.lower()
        else:
            raise EngineError('Invalid proto value: {}'.format(v))

    @states.setter
    def states(self, v):

        if v is None:
            self._states = v

        elif not all(x in ['open', 'closed', 'filtered'] for x in v):
            raise EngineError('PyNSEScript states must be "open", "closed" or "filtered".')

        else:
            self._states = v


class NSE:
    """ Represents the NSE (Nmap Script Engine). It is used to instantiate an object that is passed to the
    NmapScanner __init__ or scan() methods and it registers new "Python NSE scripts", that are function written in Python. These
    functions execute depending on the conditions defined by the user, and they can be host or port oriented.
    Several decorators are offered to make it easy for the user to include new functions.

    NSE objects can also register parsers, which are Python functions that automatically parser Nmap scripts outputs. Global parsers are 
    always executed on every script output, while normal parses only parsers specifici scripts.
    """

    __slots__ = ('_global_parsers', '_parsers', '_host_scripts', '_port_scripts')


    def __init__(self):
        
        self._global_parsers = []
        self._parsers = {}

        self._host_scripts = []
        self._port_scripts = []

    def add_port_script(self, func: Callable, name: str, targets: Union[str,Iterable], port: Union[int,str,Iterable], 
                        proto: Union[None,str,Iterable], states: Union[None,Iterable]):
        """ Register a given function to execute on a given port.

        :param func: Function to register
        :param name: Name of the function
        :param port: Port(s) affected
        :param proto: Protocol for the ports
        :param states: Valid port states
        """
        self._port_scripts.append(_NSEPortScript(name, func, targets, port, proto, states))

    def add_host_script(self, func: Callable, name: str, targets: Union[str,Iterable]):
        """ Register a given function to execute on a hosts

        :param func: Function to register
        :param name: Name of the function
        :param args: Function arguments
        """
        self._host_scripts.append(_NSEHostScript(name, func, targets))

    def add_global_parser(self, callback: Callable):
        """ Adds a function to the global parsers.
        
        :param callback: Function to be executed to parse the output
        """
        self._global_parsers.append(callback)

    def add_parser(self, script_name: str, callback: Callable):
        """ Adds a function to the parsers for a given script name
        
        :param script_name: Name of the script to parse
        :param callback: Function to execute. Must accept one parameter, which will be the script output.
        """
        if script_name in self._parsers:
            raise EngineError('"{}" already has a parsing function'.format(script_name))
        self._parsers[script_name] = callback

    def port_script(self, name: str, port: Union[int,str,Iterable], targets: Union[str,Iterable] = '*', 
                    proto: str = '*', states: Union[None,Iterable] = None):
        """ A decorator to register the given function into the PyNSEEngine as a port script.

        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param port: Port(s) to be affected by the function
        :param targets: Targets to be affected by the function
        :param proto: Protocol of the port to be affected by the function
        :param states: List of states valid for function execution
        :param args: Function arguments
        """

        def decorator(f):
            self.add_port_script(f, name, targets, port, proto, states or ['open'])
            return f

        return decorator

    def host_script(self, name: str, targets: Union[str,Iterable] = '*'):
        """ A decorator to register the given function into the NSE as a host script

        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param targets: Targets to be affected by the function
        :returns: Function decorator
        """

        def decorator(f):
            self.add_host_script(f, name, targets)
            return f

        return decorator

    def global_parser(self):
        """ A decorator to register the given function as a NSE global parser
        
        :returns: Function docorator
        """

        def decorator(f):
            self.add_global_parser(f)
            return f
        
        return decorator
    
    def parser(self, name: str):
        """ A decorator to register the given function as a NSE parser for a given script
        
        :param name: Script name
        :returns: Function decorator
        """

        def decorator(f):
            self.global_parser(f)
            return f
        
        return decorator

    def _apply_host_scripts(self, host: Host) -> None:
        """ Execute all host scripts for a given host.

        :param host: Reference to a Host object
        """
        for i in self._host_scripts:
            if i.targets == '*' or host.ipv4 in i.targets or any(x for x in host.hostnames() if x in i.targets):
                try:
                    host._add_script(i.name, i.func(host))
                except StopExecution:
                    pass
    

    def _apply_port_scripts(self, host: Host, port: Port, service: Service) -> None:
        """ Execute all port scripts for a given host, port and service.

        :param host: Reference to a Host object
        :param port: Reference to a port object
        :param service: Reference to a service object
        """

        if not self._port_scripts:
            return
        
        for i in self._port_scripts:
            if i.targets == '*' or host.ipv4 in i.targets or any(x for x in host.hostnames() if x in i.targets):
                if (i.proto == '*' or port.protocol == i.proto) and port.number in i.ports and port.state in i.states:
                    try:
                        service._add_script(i.name, i.func(host, port, service))
                    except StopExecution:
                        pass


class NSEBlueprint(NSE):
    """ This class is responsible for auto-registering Python functions as NSE scripts, as well as script-oriented and global parsers,
    depending on the name of the methods themselves. To dynamically add anything of the previously mentioned, methods from classes inheriting
    from NSEBlueprint must follow a few conventions. For a better explanation, lets divide the method name into two parts: 
    1) Dynamic definition name
    2) Reference name

    A custom NSE method should be written as follow: def [Dynamic definition name] + [Reference name](self, arg1, arg2....):
    You have 4 choices to select for the Dynamic definition name:

    - 'host_script_' will be registered as host scripts
    - 'port_script_' will be registered as port scripts
    - 'parser_' will be registered as parsers
    - 'global_parser' will be registered as global parsers

    Any other methods that do not start with this strings, will not be processed by NSEBlueprint, acting as normal methods.

    Now the Reference name. The name that would be assigned into Nmapthon's NSE object for later retrieving the scripts output, or to know which 
    script may a specific parser affect, depends on the Reference name part. NSEBlueprint takes that Reference name and transforms it to snaked-dashed-case.
    (this-is-snake-dashed-case).

    So for example, having these methdos will act as described:
        def host_script_dns_brute_force(self, host): -> Creates a host script that will be later retrieved under 'dns-brute-force' name.
        def port_script_ssh_brute(self, host, port, service): -> Creates a port script that will be later retrieved under 'ssh-brute' name.
        def global_parser_script_chars(self, output): -> In case of a global parser, it does not matter the Reference name, as it is not linked with a script name.
        def parser_http_title(self, output): -> Will register an specific parser for the 'http-title' script. 

    Note that this methods, apart from the self parameter, must except the same parameters as if they were not object-oriented. This means that
    if you would define a host script like:
        @host_script('custom-script', targets='*')
        def my_own_host_script(host):
            print(host)
            return None
    
    The equivalent class method may be:

        def host_script_custom_script(self, host):
            print(host)
            return None
    """

    def __init__(self):
        super().__init__()
        for entry in dir(self):
            # if entry.startswith('host_script_'):
            #     print(getattr(self, entry).__name__ ==)
            #     script_name = self._to_snake_dashed_case(entry[12:])
            #     self.add_host_script(getattr(self, entry), script_name, '*')
            # elif entry.startswith('port_script_'):
            #     print(getattr(self, entry).__name__)
            #     script_name = self._to_snake_dashed_case(entry[12:])
            #     self.add_port_script(getattr(self, entry), script_name, '*', 135, '*', ['open'])
            # elif entry.startswith('parser_'):
            #     script_name = self._to_snake_dashed_case(entry[7:])
            #     self.add_parser(script_name, getattr(self, entry))
            # elif entry.startswith('global_parser_'):
            #     script_name = self._to_snake_dashed_case(entry[14:])
            #     self.add_global_parser(getattr(self, entry))
            reference = getattr(self, entry)
            try:
                if reference.__name__ == '_host_script_wrapper':
                    print(reference.__name__)
            except AttributeError:
                pass
    
    @staticmethod
    def _to_snake_dashed_case(name):
        """ Transforms a cammelCase name or snake_case name into snake-dashed name.
        
        :returns: Name in snake dashed case 
        """

        return  _CAMMEL_CASE_SUBSTITUTION_REGEX.sub('-', name).replace('_', '-').lower()