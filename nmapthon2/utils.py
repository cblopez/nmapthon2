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
import socket
import struct

from collections.abc import Iterable

from .exceptions import InvalidPortError, MalformedIpAddressError

_BASE_IP_REGEX = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])'
_SINGLE_IP_ADDRESS_REGEX = re.compile('^{}$'.format(_BASE_IP_REGEX))
_IP_ADDRESS_WITH_CIDR_REGEX = re.compile('^{}/([0-9]|[1-2][0-9]|3[0-2])$'.format(_BASE_IP_REGEX))
_IP_RANGE_REGEX = re.compile('^{}-{}$'.format(_BASE_IP_REGEX, _BASE_IP_REGEX))
_OCTECT_RANGE_REGEX = '(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))'
_PARTIAL_IP_RANGE_REGEX = re.compile('{}(-{})?\.{}(-{})?\.{}(-{})?\.{}(-{})?'.format(*[_OCTECT_RANGE_REGEX for _ in range(8)]))


def valid_port(port) -> bool:
    """Checks if a given value might be a port. 
    Must be between 1 and 65535, both included.

        :param port: Port candidate
        :returns: True if is valid, False if not
    """
    try:
        int_port = int(port)
    except ValueError:
        return False

    return 0 < int_port < 65536


def ports_to_list(ports: str):
    """ Returns a list containing all ports specified in 
    a nmap-format port string.

    :param ports: String that specifies the ports to scan
    :return: List containing the ports to scan as Strings.
    :raises: InvalidPortError

    Example:
        ports               return
        '10,20,30'          ['10', '20', '30']
        '10-13'             ['10'. '11', '12', '13']
        '80, 81-83'         ['80', '81', '82', '83']
    """
    # Create empty list and delete any blank spaces
    port_list = []
    # Delete blank spaces
    ports_string = ports.replace(' ', '')

    # For every comma separated block
    for split_ports in ports_string.split(','):
        # If there is a range indicator.
        if '-' in split_ports:
            # Split the range
            port_range = split_ports.split('-')
            # Cast to integer the starting port range number.
            try:
                first_port_range = int(port_range[0])
            # If ValueError, non valid port, format the InvalidPortError message.
            except ValueError:
                first_port = port_range[0] if len(port_range[0]) else 'None'
                raise InvalidPortError('Invalid starting port range: {}'.format(first_port)) from None
            # Cast ending port range
            try:
                last_port_range = int(port_range[1]) + 1
            # If IndexError, no ending port range was specified.
            except IndexError:
                raise InvalidPortError('End of port range in {}- not specified'.format(port_range[0])) from None
            # If ValueError, invalid ending for port range.
            except ValueError:
                raise InvalidPortError('Invalid ending port range: {} '.format(port_range[1])) from None
            # For every port in the range calculated
            for single_port in range(first_port_range, last_port_range):
                # If valid port, add to list
                if valid_port(single_port):
                    port_list.append(single_port)
                # If invalid, raise Exception
                else:
                    raise InvalidPortError('{} is not a valid port'.format(single_port))

        # If no range indicators, guess individual port
        else:
            # If split port has length
            if len(split_ports):
                # Cast to integer value
                try:
                    integer_parsed_port = int(split_ports)
                # If ValueError, malformed
                except ValueError:
                    raise InvalidPortError('Invalid port: {}'.format(split_ports)) from None
                # If is a valid port, append it to list
                if valid_port(integer_parsed_port):
                    port_list.append(integer_parsed_port)
                # If invalid, raise Error
                else:
                    raise InvalidPortError('{} is not a valid port.'.format(integer_parsed_port))
    
    return sorted(list(set(port_list)))

def extend_port_list(port_list: Iterable) -> list:
    """ Transforms a port list with single ports and/or port ranges 
    into a single list with no duplicates.

    :param port_list: Port list to parse
    :returns: List of single and unique ports
    """

    # To STR
    port_list = list(map(str, port_list))

    new_port_list = []
    for i in list(map(ports_to_list, port_list)):
        new_port_list.extend(i)
    
    return list(set(new_port_list))


def ports_to_str(port_list: Iterable) -> str:
    """ Parse a list of int/str ports into a single str containing a 
    port range that nmap can understand.

        :param port_list: List of ports
        :return: String representing the ports in nmap syntax
    """

    # Get unique list of single ports
    new_port_list = extend_port_list(port_list)

    # If not all ports are valid ports, raise NmapScanError
    if not all(valid_port(p) for p in new_port_list):
        raise InvalidPortError('Ports must be between 0 and 65536') from None

    # Sort ports in ascending order
    sorted_ports = sorted(new_port_list)
    # Instantiate port string
    port_string = ''
    # Instantiate last port variable
    last_port = -2
    # Loop through sorted_ports list, bust access the ports by position.
    # Used to know when the list is about to finish
    i = 0
    while i < len(sorted_ports):
        # If the current port is not the immediate next one
        if sorted_ports[i] != (last_port + 1):
            port_string += str(sorted_ports[i])
            # Set last_port to current port
            last_port = sorted_ports[i]
            # Append a comma if the port is not the last one
            if i != (len(sorted_ports) - 1) and sorted_ports[i + 1] != (sorted_ports[i] + 1):
                port_string += ','
            # Add one to i
            i += 1
        # If the current port is the previous port plus 1
        else:
            # Add a dash (range indicator)
            port_string += '-'
            # Set last_port to current port
            last_port = sorted_ports[i]
            # Add one to i
            i += 1
            # keep going if next ports are immediate next
            while i < len(sorted_ports) and sorted_ports[i] == (last_port + 1):
                last_port = sorted_ports[i]
                i += 1
            # On exit of while loop, range ends, write last port range
            port_string += str(last_port)
            # Append a comma if the port is not the last one
            if i != len(sorted_ports):
                port_string += ','

    return port_string

def valid_ip(ip_address: str) -> bool:
    """Checks if a given IP address is correctly formed.

        :param ip_address: IP address to check
        :return: True if it is a valid IP Address, False if not
    """

    # Return True if matches, False if not.
    if _SINGLE_IP_ADDRESS_REGEX.fullmatch(ip_address):
        return True
    else:
        return False


def ip_range(starting_ip: str, ending_ip: str) -> list:
    """ Calculates a list of IPs between two given.

        :param starting_ip: Range starting IP address
        :param ending_ip: Range ending IP address
        :returns: List of ports between two given IPs
    """

    # Create a list contaning the 4 octets from both IP address in decimal format.
    split_starting_ip = list(map(int, starting_ip.split('.')))
    split_ending_ip = list(map(int, ending_ip.split('.')))
    # Create list of IPs to return, starting with the first one.
    ip_range = [starting_ip]

    # Execute algorithm. While you can add one to the most on the right octet, keep going
    # and add. If the 4 octets are named from 3 to 0 from left to right: when octet N is 255,
    # set octet N to 0 and add one to octet N+1
    while split_starting_ip != split_ending_ip:
        split_starting_ip[3] += 1
        for i in [3, 2, 1]:
            if split_starting_ip[i] == 256:
                split_starting_ip[i] = 0
                split_starting_ip[i - 1] += 1
        # Reformat to IP address-like string.
        current_ip = '.'.join(map(str, split_starting_ip))
        ip_range.append(current_ip)

    return ip_range


def partial_ip_range(ip_addr: str) -> list:
    """ Calculates the list of IP address from a partial ranged IP expression.

        :param ip_addr: IP Address from where to extract the IPs
        :returns: List of IPs in partial range
    """

    # Split by dots
    split_ip = ip_addr.split('.')
    # IPs to return
    ips=[]
    # List to store each part range
    partial_ranges = []
    # For each partial IPs part
    for i in split_ip:
        # If its a range
        if '-' in i:
            # Extract the list of numbers between
            partial_range = i.split('-')
            try:
                start = int(partial_range[0])
            except ValueError:
                raise MalformedIpAddressError('Invalid start of range, expected number but got : {}'.format(partial_range[0]))
            try:
                end = int(partial_range[1])
            except ValueError:
                raise MalformedIpAddressError('Invalid start of range, expected number but got : {}'.format(partial_range[1]))

            if not 0 <= start <= end <= 255:
                raise MalformedIpAddressError('Start range must be lower than end range, and both between 0 adn 255')

            partial_ranges.append(list(range(start, end + 1)))

        # If not, add a list with a single element
        else:
            partial_ranges.append([i])
    
    # Combine them all
    # TODO: Beautify this
    for one in partial_ranges[0]:
        for two in partial_ranges[1]:
            for three in partial_ranges[2]:
                for four in partial_ranges[3]:
                    ips.append('{}.{}.{}.{}'.format(one, two, three, four))
    
    return ips


def dispatch_network(network: str) -> list:
    """ Creates a list of all the IP address inside a network with 
    it's net-mask in CIDR format.

        :param network: Network IP address and /net-mask to dispatch
        :returns: List of every IP on a network range
        :raises: MalformedIPAddressError
    """

    # List to return
    ip_addresses = []

    # Delete blank spaces and split IP Address and netmask in CIDR format.
    ip_address_netmask = network.replace(' ', '').split('/')
    # If not split in two parts, raise Exception.
    if len(ip_address_netmask) != 2:
        raise MalformedIpAddressError('Invalid network to dispatch: {}.'
                                      ' Need an IP address and CIDR Mask like 192.168.1.0/24'
                                      .format(ip_address_netmask))

    # IP Address is the first part
    ip_address = ip_address_netmask[0]

    # CIDR is the second part
    try:
        cidr = int(ip_address_netmask[1])
    # If cannot convert to integer, raise Exception
    except ValueError:
        raise MalformedIpAddressError('Invalid CIDR format: {}'.format(ip_address_netmask[1])) from None

    # If netmask not between 0 and 32, included, raise Exception
    if not 0 <= cidr <= 32:
        raise MalformedIpAddressError('Out of range CIDR: {}'.format(cidr))

    # If invalid IP address, raise Exception
    if not valid_ip(ip_address):
        raise MalformedIpAddressError('Invalid network IP: {}.'.format(ip_address))

    # Combination from struct and socket for binary formatting and bit level operations.
    # Getting every IP address inside a network range (established by netmask).
    host_bits = 32 - cidr
    aux = struct.unpack('>I', socket.inet_aton(ip_address))[0]
    start = (aux >> host_bits) << host_bits
    end = start | ((1 << host_bits) - 1)

    for ip in range(start, end):
        ip_addresses.append(socket.inet_ntoa(struct.pack('>I', ip)))

    # Return every IP address but not Network Address
    return ip_addresses[1:]


def targets_to_list(targets: str) -> list:
    """ Returns a list containing all targets specified for the scan.

        :param targets: String that specifies the targets to scan
        :return: List containing the targets to scan as Strings.
        :raises: MalformedIPAddressError

        Example:
            targets                             return
            '192.168.1.1 192.168.1.2'          ['192.168.1.1', '192.168.1.2']
            '192.168.1.1-192.168.1.3'           ['192.168.1.1', '192.168.1.2', '192.168.1.3']
            '192.168.1.0/30'                    ['192.168.1.1', '192.168.1.2']

        note:
            If network/cidr mask is specified, both Network address and broadcast address will be omitted.
    """

    # List to return
    target_list = []

    # For each block split by a comma.
    for split_target in targets.split(' '):
        if not split_target:
            continue
        # If range indicator
        if _IP_RANGE_REGEX.fullmatch(split_target):
            # Split range
            ip_range_list = split_target.split('-')
            # Get starting IP address from range
            starting_ip = ip_range_list[0]
            # If not a valid IP address, raise Error
            if not valid_ip(starting_ip):
                raise MalformedIpAddressError('Invalid starting IP range: {}'.format(starting_ip))
            # Get Ending IP address from range
            ending_ip = ip_range_list[1]
            # If not valid IP address, raise Error
            if not valid_ip(ending_ip):
                raise MalformedIpAddressError('Invalid ending IP range: {}'.format(ending_ip))
            # For every IP in range, add to list if valid IP. If not, raise Exception.
            for single_target_in_range in ip_range(starting_ip, ending_ip):
                if valid_ip(single_target_in_range):
                    target_list.append(single_target_in_range)
                else:
                    raise MalformedIpAddressError('Invalid IP Address: {}'.format(single_target_in_range))
        # If a slash is found, guess a network mask
        elif _IP_ADDRESS_WITH_CIDR_REGEX.fullmatch(split_target):
            # Extend the list for dispatching the network
            target_list.extend(dispatch_network(split_target))

        # If partial IP addresses
        elif _PARTIAL_IP_RANGE_REGEX.fullmatch(split_target):
            target_list.extend(partial_ip_range(split_target))

        # If it reaches here, guess single IP. Add to list or raise Error if malformed.
        else:
            target_list.append(split_target)

    # Return the sorted list. List is sorted by IP address. Ej: 192.168.1.12 > 192.168.1.9
    return list(set(target_list))

