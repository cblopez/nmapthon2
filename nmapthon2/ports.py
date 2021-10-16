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
from .exceptions import InvalidPortError


class _PortAbstraction:
    """ Encapsulates the logic for using tcp() and udp() functions together, and
    generates the different syntax to be used for Nmap depending on the 
    selected options.
    """

    def __init__(self, port_range):
        self._tcp_ports = None
        self._udp_ports = None

        # Flags
        self._has_added_tcp = False
        self._has_added_udp = False

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
            elif port_range == 'default':
                return None
            
            # In any other case, suppose that it is an str port range
            # Execute ports to list to raise any possible InvalidPortError
            _ = utils.ports_to_list()
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
            raise 

        if port_range:
            self._tcp_ports.append(self._parse_port_range(port_range))

def tcp(port_range):
    """ Returns TCP like syntax for port scanning.

    :param port_range: String or Iterable of ports to set to the Nmap command.
    :returns: String representing the TCP port range
    """
    
    parsed_port_range = _parse_port_range(port_range)
    if parsed_port_range:
        return 'T:{}'.format(parsed_port_range)
    
    return None


def udp(port_range):
    """ Returns UDP like syntax for port scanning.

    :param port_range: String or Iterable of ports to set to the Nmap command.
    :returns: String representing the TCP port range
    """
    
    parsed_port_range = _parse_port_range(port_range)
    if parsed_port_range:
        return 'U:{}'.format(parsed_port_range)
    
    return None


def top_ports(num_ports):
    """ Returns Nmap-like syntax for top ports

    :param num_ports: Number of ports
    """

    return '--top-ports {}'.format(num_ports)