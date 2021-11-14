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

from typing import Iterable, Union, Callable, get_type_hints

from .utils import targets_to_list, ports_to_list, extend_port_list
from .exceptions import EngineError, StopExecution
from .elements import Host, Port, Service


class _DelayedParserAbstraction:

    def __init__(self, script_name, func) -> None:
        self.script_name = script_name
        self.func = func

class NSEMeta(type):

    def __init__(cls, name, bases, attrs):

        _delayed_registry_set = set()
        for name, method in attrs.items():
            if isinstance(method, property):
                method = method.fget
            if hasattr(method, '_delayed_registry'):
                _delayed_registry_set.add(getattr(method, '_delayed_registry'))

        @property
        def _delayed_registry(self):
            registries = _delayed_registry_set.copy()
            try:
                registries.update(super(cls, self)._delayed_registry_set)
            except AttributeError:
                pass
            return registries
        
        cls._delayed_registry = _delayed_registry


def host_script(name: str, targets: Union[str,Iterable] = '*'):
    """ Decorator to be used from a class inheriting NSE, that automatically adds the decorated function as 
        an NSE host script with the function name in snake case separated by dashes.
        
        :param targets: Targets that may be affected by the script
        :returns: Funciton decorator
    """
    def inner(f):
        f._delayed_registry = _NSEHostScript(name, f, targets, delayed=True)
        return f
    return inner


def port_script(name: str, port: Union[int,str,Iterable], targets: Union[str,Iterable] = '*', 
                proto: str = '*', states: Union[None,Iterable] = None):
    
    def inner(f):
        f._delayed_registry = _NSEPortScript(name, f, targets, port, proto, states)
        return f
    return inner


def parser(script_name: str):

    def inner(f):
        f._delayed_registry = _DelayedParserAbstraction(script_name, f)
        return f
    return inner

class _NSEHostScript:
    """ An individual Python function that is executed as if it were an Nmap NSE host script.
    The script is represented by a name, a function to execute per alive host and the arguments to the function.
        :param name: Name of the function (PyNSEScript name)
        :param func: Function to execute
        :param args: Arguments for the function
        :param delayed: Delayed lets the NSE object know that the script has been registered through a class, meaning 
                        that I will need to register after instantiation (delayed registry).
    """

    __slots__ = ('_name', '_func', '_targets', '_delayed')

    def __init__(self, name: str, func: Callable, targets: Union[str, Iterable], delayed: bool = False):
        self.name = name
        self.func = func
        self.targets = targets
        self.delayed = delayed

    @property
    def name(self):
        return self._name

    @property
    def func(self):
        return self._func

    @property
    def targets(self):
        return self._targets

    @property
    def delayed(self):
        return self._delayed

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
    
    @delayed.setter
    def delayed(self, v):
        assert isinstance(v, bool), 'NSEHostScript.delayed must be of bool type'
        self._delayed = v

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


class NSE(metaclass=NSEMeta):
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

        for i in self._delayed_registry:
            if isinstance(i, _NSEPortScript):
                self._port_scripts.append(i)
            elif isinstance(i, _NSEHostScript):
                self._host_scripts.append(i)
            elif isinstance(i, _DelayedParserAbstraction):
                self._parsers[i.script_name] = getattr(self, i.func.__name__)
            else:
                raise EngineError('Could not add NSE script to engine. Unkown type: {}'.format(type(i)))

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
                    if i.delayed:
                        host._add_script(i.name, getattr(self, i.func.__name__)(host))
                    else:
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
                        if i.delayed:
                            service._add_script(i.name, getattr(self, i.func.__name__)(host, port, service))
                        else:
                            service._add_script(i.name, i.func(host, port, service))
                    except StopExecution:
                        pass
