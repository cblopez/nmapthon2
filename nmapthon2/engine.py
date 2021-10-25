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

from .utils import targets_to_list, ports_to_list, extend_port_list

from .exceptions import EngineError
from inspect import signature


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

    def __init__(self, name, func, targets, args):
        self.name = name
        self.func = func
        self.targets = targets
        self.args = args

        self.current_target = None

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
    def args(self):
        return self._args

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

    @args.setter
    def args(self, v):
        if v is None:
            self._args = []
        else:
            number_args = len(str(signature(self.func)).split(','))
            if not isinstance(v, list) and not isinstance(v, tuple):
                raise EngineError('Invalid args data type: {}'.format(type(v)))
            if number_args != len(v):
                raise EngineError('Number of function arguments does not match with specified arguments')

            self._args = v

    def execute(self):
        """ Runs the function with the specific arguments and returns the output
        """
        if self.args is None:
            return self.func()
        else:
            return self.func(*self.args)


class _NSEPortScript(_NSEHostScript):
    """ Represents an NSE port script
    As well as those scripts, it can have any number of arguments and it can assign output to the NmapScanner object.
    The functions are only executed if the port or host (depending on the function type) is open,
    but the user can also specify which of the three port states ('open', 'filtered'or 'closed') are valid for the
    function to execute.
        :param ports: Port or ports to target. A None value means it is a host script
        :param proto: Transport layer protocol ('tcp', 'udp' or '*' for both)
        :param states: List of states valid for function execution
        :type ports: str, int, list
        :type proto: str
        :type states: list, tuple
    """

    def __init__(self, name, func, targets, args, ports, proto, states):
        super().__init__(name, func, targets, args)
        self.ports = ports
        self.proto = proto
        self.states = states

        self.current_port = None
        self.current_proto = None

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
    """ Represents the Nmap NSE script engine. It is used to instantiate an object that is passed to the
    NmapScanner __init__ method and it registers new "Python NSE scripts", that are function written in Python. These
    functions execute depending on the states defined by the user, and they can be host or port oriented.
    Several decorators are offered to make it easy for the user to include new functions.
    """

    def __init__(self):
        
        self._parsers = {}

        self._host_scripts = []
        self._port_scripts = []

        self.current_target = None
        self.current_port = None
        self.current_proto = None
        self.current_state = None

    def _register_port_script(self, func, name, targets, port, proto, states, args):
        """ Register a given function to execute on a given port.

        :param func: Function to register
        :param name: Name of the function
        :param port: Port(s) affected
        :param proto: Protocol for the ports
        :param states: Valid port states
        :type func: function
        :type name: str
        :type port: str, int, list
        :type proto: str
        :type states: None, list
        :type args: None, list, tuple
        """
        self._port_scripts.append(_NSEPortScript(name, func, targets, args, port, proto, states))

    def _register_host_script(self, func, name, targets, args=None):
        """ Register a given function to execute on a hosts

        :param func: Function to register
        :param name: Name of the function
        :param args: Function arguments
        :type func: function
        :type name: str
        :type args: None, list, tuple
        """
        self._host_scripts.append(_NSEHostScript(name, func, targets, args))

    def add_parser(self, script_name: str, callback):
        """ Adds a function to the parsers for a given script name
        
        :param script_name: Name of the script to parse
        :param callback: Function to execute. Must accept one parameter, which will be the script output.
        """
        if script_name in self._parsers:
            raise EngineError('"{}" already has a parsing function'.format(script_name))
        self._parsers[script_name] = callback

    def port_script(self, name, port, targets='*', proto='*', states=None, args=None):
        """ A decorator to register the given function into the PyNSEEngine as a port script.

        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param port: Port(s) to be affected by the function
        :param targets: Targets to be affected by the function
        :param proto: Protocol of the port to be affected by the function
        :param states: List of states valid for function execution
        :param args: Function arguments
        :type name: str
        :type port: list, int, str
        :type targets: str, list
        :type proto: str
        :type states: None, list
        :type args: None, tuple, list
        """

        def decorator(f):
            self._register_port_script(f, name, targets, port, proto, states or ['open'], args)
            return f

        return decorator

    def host_script(self, name, targets='*', args=None):
        """ A decorator to register the given function into the PyNSEEngine as a host script
        :param name: Name of the function/script to be used later on to retrieve the information gathered by it.
        :param targets: Targets to be affected by the function
        :param args: Function arguments
        :type name: str
        :type targets: str
        :type args: None, list, tuple
        """

        def decorator(f):
            self._register_host_script(f, name, targets, args)
            return f

        return decorator

    def get_suitable_host_scripts(self, target):
        """ Yield the host scripts for a given target.

        :param target: Target of the scripts
        :type target: str
        """
        for i in self._host_scripts:
            if (isinstance(i.targets, list) and target in i.targets) or (i.targets == '*' or i.targets == target):
                self.current_target = target
                yield i

    def get_suitable_port_scripts(self, target, proto, port, state):
        """ Yield the port scripts for a given target, protocol, port and port state
        :param target: Target of the scripts
        :param proto: Transport layer protocol
        :param port: Target port
        :param state: Target port state
        :type target: str
        :type proto: str,
        :type port: int, str
        :type state: str
        """
        
        for i in self._port_scripts:
            if target in i.targets or i.targets == '*':
                if (i.proto == '*' or proto == i.proto) and int(port) in i.ports and state in i.states:
                    self.current_target = target
                    self.current_proto = proto
                    self.current_port = port
                    self.current_state = state

                    yield i
