#!/usr/bin/env python3

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
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


# This module contains the XML parser used to transform 
# pure Nmap XML output into Python objects.


from collections.abc import Iterable

from . import utils
from .exceptions import InvalidArgumentError, InvalidPortError


class _PortAbstraction:
    """ Encapsulates the logic for using tcp(), udp() and top_ports() functions together, and
    generates the different syntax to be used for Nmap depending on the 
    selected options.

    A user may not select TCP or UDP ports twice, and a user may not either select top_ports with other TCP or UDP ports.
    """

    def __init__(self):
        self._tcp_ports = None
        self._udp_ports = None
        self._top_ports = None
        self._malleable_ports = None

        # Flags
        self._has_added_tcp = False
        self._has_added_udp = False
        self._has_added_top_ports = False
        self._has_added_malleable = False

    @staticmethod
    def _parse_port_range(port_range):
        """ Parses a port range, depending on if its an str or an Iterable.

        :param port_range: Port range to parse
        :returns: String representing the port range.
        """

        # If string
        if isinstance(port_range, str):
            port_range = port_range.strip()

            # If port range is a word
            if port_range == 'all' or port_range == '*':
                return '-'
            
            # In any other case, suppose that it is an str port range
            # Execute ports to list to raise any possible InvalidPortError
            _ = utils.ports_to_list(port_range)
            return port_range
        
        # If iterable
        elif isinstance(port_range, Iterable):

            return utils.ports_to_str(port_range)
        
        # In any other case, raise error
        else:
            raise TypeError('Invalid port_range type: {}, expected str or Iterable'.format(type(port_range)))

    def tcp(self, port_range):
        """ Adds a port range to the TCP port selection.
        """

        if self._has_added_tcp:
            raise InvalidPortError('Cannot add TCP ports twice.')
        
        if self._has_added_top_ports:
            raise InvalidPortError('Cannot specify top ports and individual ports on a same scanner.')

        if port_range:
            self._tcp_ports = self._parse_port_range(port_range)
        
        self._has_added_tcp = True
        return self
    
    def udp(self, port_range):
        """ Adds a port range to the UDP port selection.
        """

        if self._has_added_udp:
            raise InvalidPortError('Cannot add UDP ports twice.')
        
        if self._has_added_top_ports:
            raise InvalidPortError('Cannot specify top ports and individual ports on a same scanner.')
        
        if port_range:
            self._udp_ports = self._parse_port_range(port_range)
        
        self._has_added_udp = True
        return self
    
    def top_ports(self, num_ports):
        """ Adds a --top-ports nmap parameter with num_ports
        
        :param num_ports: Number of ports to add to the scanner.
        :returns: Instance of the object itself
        """

        if self._has_added_tcp or self._has_added_udp:
            raise InvalidPortError('Cannot specify UDP and TCP when also specifying top ports.')

        try:
            num_ports = int(num_ports)
        except ValueError:
            raise InvalidPortError('Invalid top_ports value, expected int but got {}'.format(type(num_ports)))
        
        if not 1 <= num_ports <= 65535:
            raise InvalidPortError('Invalid top_ports value, must be between 1 and 65535')
        
        self._top_ports = num_ports
        self._has_added_top_ports = True

        return self

    def _malleable(self, port_range):
        """ Adds a malleable port range. 
        
        Malleable ports are those that are protocol-specific. This means that a user may specify ports without the tcp() or udp() functions/methods.
        so the protocol to be used with those ports depends on the user specifying -sU, any other option or -sU + any other option. In this case, malleable ports
        should not be added to the raw nmap command with T: or U:
        
        :param port_range: Port range to add.
        :returns: Instance of the object itself
        """

        # Since this is an internal function that should NOT be used directly, no other checks are needed
        if port_range:
            self._malleable_ports = self._parse_port_range(port_range)
        
        self._has_added_malleable = True
        return self
        
    
    def to_nmap_syntax(self):
        """ Based on the object data, it returns a valid nmap string that can be directly injected into an nmap command.

        :returns: String with nmap-like syntax
        """

        if self._has_added_malleable:
            return self._malleable_ports

        elif self._top_ports:
            return '--top-ports {}'.format(self._top_ports)

        elif self._tcp_ports or self._udp_ports:
            nmap_port_string = ''
            if self._tcp_ports:
                nmap_port_string += 'T:{}'.format(self._tcp_ports)
            if self._udp_ports:
                nmap_port_string += 'U:{}'.format(self._udp_ports)
            
            return nmap_port_string
        
        else:
            return None


def tcp(port_range):
    """ Returns a TCP port range encapsulated into a PortAbstraction object

    :param port_range: String or Iterable of ports to set to the Nmap command.
    :returns: Instance of _PortAbstraction with the added port_range as TCP ports
    """
    
    return _PortAbstraction().tcp(port_range)


def udp(port_range):
    """ Returns a UDP port range encapsulated into a PortAbstraction object

    :param port_range: String or Iterable of ports to set to the Nmap command.
    :returns: Instance of _PortAbstraction with the added port_range as UDP ports
    """
    
    return _PortAbstraction().udp(port_range)


def top_ports(num_ports):
    """ Returns Nmap-like syntax for top ports

    :param num_ports: Number of ports
    """

    return _PortAbstraction().top_ports(num_ports)