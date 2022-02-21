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


class _DelayedGlobalParserAbstraction:
    """ Represents a global parser that would be registered through OOP
    """
    def __init__(self, func) -> None:
        self.func = func


class _DelayedParserAbstraction(_DelayedGlobalParserAbstraction):
    """ Represents a parser that would be registered through OOP
    """
    def __init__(self, script_name, func) -> None:
        super().__init__(func)
        self.script_name = script_name


class NSEMeta(type):
    """ Metaclass to represent the behaivor for registering class methods as NSE scripts for Object-Oriented engines.

    It defines a set to store the functions for dalayed registry, which means, methods that will have to be added after instatiating the object
    subclassing NSE. It marks them with a flag (a protected attribute) for further registering them depending on the instance type.
    """
    def __init__(cls, name, bases, attrs):

        _delayed_registry_set = set()
        for _, method in attrs.items():
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
        
        # This is used to propagate through the hierarchy
        cls._delayed_registry = _delayed_registry


def host_script(name: str, targets: Union[str,Iterable] = '*'):
    """ Decorator to be used from a class inheriting NSE, that automatically adds the decorated method as 
        an NSE host script with the specified name.
        
        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param targets: Targets to be affected by the function. Specify them the same way as you specify scan targets. '*' would be all of them.
        :returns: Funciton decorator
    """
    def inner(f):
        f._delayed_registry = _NSEHostScript(name, f, targets, delayed=True)
        return f
    return inner


def port_script(name: str, ports: Union[int,str,Iterable], targets: Union[str,Iterable] = '*', 
                proto: str = '*', states: Union[None,Iterable] = None):
    """ Decorator to be used from a class inheriting NSE, that registers the given function into the NSE as a port script.

        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param ports: Port(s) to be affected by the function. You can specify, '*' to target all ports. You can also set them the
                    same way as ports in the nmapthon2.scanner.NmapScanner.scan() method, but without the tcp(), udp() or top_ports() functions.
        :param targets: Targets to be affected by the function. Specify them the same way as you specify scan targets. '*' would be all of them.
        :param proto: Protocol of the port to be affected by the function. Default is '*', which applies to any protocol, but it can be either 'tcp' or 'udp'.
        :param states: List of states valid for function execution, can be a list with the following values in it: 'open', 'filtered' and/or 'closed'. By default, port scripts only target open ports
    """
    def inner(f):
        f._delayed_registry = _NSEPortScript(name, f, targets, ports, proto, states)
        return f
    return inner


def parser(script_name: str):
    """ Decorator to be used from a class inheriting NSE, that registers the given function as a NSE parser for a given script
        
        :param name: Script name
        :returns: Function decorator
    """
    def inner(f):
        f._delayed_registry = _DelayedParserAbstraction(script_name, f)
        return f
    return inner

def global_parser(f):
    """Decorator to be used from a class inheriting NSE, that registers the given function as a NSE global parser
        
        :returns: Function docorator
    """
    def inner():
        f._delayed_registry = _DelayedGlobalParserAbstraction(f)
        return f
    return inner


class _NSEHostScript:
    """ An individual Python function that is executed as if it were an Nmap NSE host script.
    The script is represented by a name and a function to execute per alive host.

        :param name: Name of the function (PyNSEScript name)
        :param func: Function to execute
        :param targets: Filter to specify which targets should be affected by the function.
        :param delayed: Delayed allows the NSE object know that the script has been registered through a class, meaning 
                        that it will need to register after instantiation (delayed registry).
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
    """ Represents an NSE port script.
    As well as those scripts, it can have any number of arguments and it can assign output to the NmapScanResult object.
    The functions are only executed if the port or host (depending on the function type) is open,
    but the user can also specify which of the three port states ('open', 'filtered'or 'closed') are valid for the
    function to execute.
        :param ports: Port or ports to target.
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
        elif isinstance(v, (int, str)):
            self._ports = ports_to_list(str(v))

        elif isinstance(v, Iterable):
            self._ports = extend_port_list(v)

        else:
            raise EngineError('Invalid ports data type: {}'.format(type(v)))

    @proto.setter
    def proto(self, v):
        if v is None:
            self._proto = None
        elif isinstance(v, str) and v.lower() in ['tcp', 'udp', '*']:
            self._proto = v.lower()
        else:
            raise EngineError('Invalid proto value: {} ({})'.format(v, type(v)))

    @states.setter
    def states(self, v):

        if v is None:
            self._states = ['open']

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
            elif isinstance(i, _DelayedGlobalParserAbstraction):
                self._global_parsers.append(getattr(self, i.func.__name__))
            else:
                raise EngineError('Could not add NSE script to engine. Unkown type: {}'.format(type(i)))

    def add_port_script(self, func: Callable, name: str, port: Union[int,str,Iterable], targets: Union[str,Iterable] = '*', 
                        proto: Union[None,str,Iterable] = '*', states: Union[None,Iterable] = None):
        """ Register a given function to execute on a given port.

        :param func: Function to register
        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param port: Port(s) to be affected by the function. You can specify, '*' to target all ports. You can also set them the
                    same way as ports in the nmapthon2.scanner.NmapScanner.scan() method, but without the tcp(), udp() or top_ports() functions.
        :param targets: Targets to be affected by the function. Specify them the same way as you specify scan targets. '*' would be all of them.
        :param proto: Protocol of the port to be affected by the function. Default is '*', which applies to any protocol, but it can be either 'tcp' or 'udp'.
        :param states: List of states valid for function execution, can be a list with the following values in it: 'open', 'filtered' and/or 'closed'. By default, port scripts only target open ports
    
        """
        self._port_scripts.append(_NSEPortScript(name, func, targets, port, proto, states))

    def add_host_script(self, func: Callable, name: str, targets: Union[str,Iterable] = '*'):
        """ Register a given function to execute on a hosts

        :param func: Callback function to register
        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param targets: Targets to be affected by the function. Asterik means all of them, but they can be specified the same way as you specify targets in the scan() method, including network ranges, partial ranges, etc...
        """
        self._host_scripts.append(_NSEHostScript(name, func, targets))

    def add_global_parser(self, callback: Callable):
        """ Adds a function to the global parsers.
        
        :param callback: Function to be executed to parse the output
        """
        self._global_parsers.append(callback)

    def add_parser(self, callback: Callable, script_name: str):
        """ Adds a function to the parsers for a given script name
        
        :param script_name: Name of the script to parse
        :param callback: Function to execute. Must accept one parameter, which will be the script output.
        :raises EngineError: Whenever the engine already has a registered function for the given script name.
        """
        if script_name in self._parsers:
            raise EngineError('"{}" already has a parsing function'.format(script_name))
        self._parsers[script_name] = callback

    def port_script(self, name: str, ports: Union[int,str,Iterable], targets: Union[str,Iterable] = '*', 
                    proto: str = '*', states: Union[None,Iterable] = None):
        """ A decorator to register the given function into the NSE as a port script.

        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param ports: Port(s) to be affected by the function. You can specify, '*' to target all ports. You can also set them the
                    same way as ports in the nmapthon2.scanner.NmapScanner.scan() method, but without the tcp(), udp() or top_ports() functions.
        :param targets: Targets to be affected by the function. Specify them the same way as you specify scan targets. '*' would be all of them.
        :param proto: Protocol of the port to be affected by the function. Default is '*', which applies to any protocol, but it can be either 'tcp' or 'udp'.
        :param states: List of states valid for function execution, can be a list with the following values in it: 'open', 'filtered' and/or 'closed'. By default, port scripts only target open ports
        """

        def decorator(f):
            self.add_port_script(f, name, ports, targets, proto, states or ['open'])
            return f

        return decorator

    def host_script(self, name: str, targets: Union[str,Iterable] = '*'):
        """ A decorator to register the given function into the NSE as a host script

        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param targets: Targets to be affected by the function. Specify them the same way as you specify scan targets. '*' would be all of them.
        :returns: Function decorator
        """

        def decorator(f):
            self.add_host_script(f, name, targets)
            return f

        return decorator

    def delete_host_script(self, name: str, silent: bool = True):
        """ Delete an existing host script. If silent, it won't rise an error when the script does not exist.

        :param silent: If False, it will raise KeyError if the script does not exist.
        """
        try:
            del self._host_scripts[name]
        except KeyError:
            if not silent:
                raise

    def delete_port_script(self, name: str, silent: bool = True):
        """ Delete an existing port script. If silent, it won't rise an error when the script does not exist.

        :param silent: If False, it will raise KeyError if the script does not exist.
        """
        try:
            del self._port_scripts[name]
        except KeyError:
            if not silent:
                raise

    def delete_parser(self, name: str, silent: bool = True):
        """ Delete an existing parser. If silent, it won't rise an error when the script does not exist.

        :param silent: If False, it will raise KeyError if the script does not exist.
        """
        try:
            del self._parsers[name]
        except KeyError:
            if not silent:
                raise

    @staticmethod
    def global_parser(f):
        """ A decorator to register the given function as a NSE global parser
        
        :returns: Function docorator
        """

        def decorator():
            self.add_global_parser(f)
            return f
        
        return decorator
    
    def parser(self, name: str):
        """ A decorator to register the given function as a NSE parser for a given script
        
        :param name: Script name
        :returns: Function decorator
        """

        def decorator(f):
            self.add_parser(f, name)
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
                if (i.proto == '*' or port.protocol == i.proto) and (i.ports == '*' or port.number in i.ports) and port.state in i.states:
                    try:
                        if i.delayed:
                            service._add_script(i.name, getattr(self, i.func.__name__)(host, port, service))
                        else:
                            service._add_script(i.name, i.func(host, port, service))
                    except StopExecution:
                        pass
