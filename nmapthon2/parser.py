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

import pathlib

import xml.etree.ElementTree as ET

from typing import Union

from .elements import Host, Port, Service, OperatingSystem, Hop
from .results import NmapScanResult
from .exceptions import XMLParsingError


class XMLParser:
    """ Used to parse Nmap outputs into Python objects.

    Parsing can occur from a plain string to a phisical XML file on
    the file system. All the information will be encapsulated into different
    Python objects. 

    Attributes:
        _xml_tree: Tree containing all the XML information
    """

    __slots__ = ('_xml_tree',)

    def __init__(self):
        self._xml_tree = None
    
    @property
    def xml_tree(self):
        return self._xml_tree

    def parse_file(self, file_path: Union[pathlib.Path,str]):
        """ Parse a XML file in the system.

        :param file_path: Path from the file as a String or a Path object.
        :raises FileNotFoundError: If file is not found and as_boolean is False.
        :returns: Parsed file as NmapScanResult.
        """

        if isinstance(file_path, pathlib.Path):
            file_path = file_path.absolute
        with open(file_path) as f:
            return self._parse(f.read())

    def parse_plain(self, plain_text: str):
        """ Parse a plain string that contains the XML.

        :param plain_text: Plain string containing the data.
        :returns: Parsed string as NmapScanResult
        """

        return self._parse(plain_text)

    def _parse(self, text: str) -> NmapScanResult:
        """ Contains the logic for parsing Nmap XML output from a string.

        :param text: Text to parse.
        :returns: Scan result
        """

        try:
            self._xml_tree = ET.fromstring(text)
        except ET.ParseError as e:
            raise XMLParsingError('Cannot parse Nmap XML output: {}'.format(e)) from None

        # Parse general scan information
        general_info = {}
        # Loop through every attribute from the root element
        for attribute, value in self._xml_tree.attrib.items():
            if attribute == 'scanner':
                general_info['scanner'] = value
            elif attribute == 'args':
                general_info['arguments'] = value
            elif attribute == 'start':
                general_info['start_timestamp'] = value
                general_info['start_datetime'] = value
            elif attribute == 'version':
                general_info['version'] = value
        
        # Loop through all elements on the <finished> element
        for attribute, value in self._xml_tree.find('.//finished').attrib.items():
            if attribute == 'time':
                general_info['end_timestamp'] = value
                general_info['end_datetime'] = value
            elif attribute == 'elapsed':
                general_info['elapsed'] = value
            elif attribute == 'summary':
                general_info['summary'] = value
            elif attribute == 'exit_status':
                general_info['exit_status'] = value
        
        # Loop through all elements on <hosts> element
        for attribute, value in self._xml_tree.find('.//hosts').attrib.items():
            if attribute == 'up':
                general_info['hosts_up'] = value
            elif attribute == 'down':
                general_info['hosts_down'] = value
            elif attribute == 'total':
                general_info['num_hosts'] = value

        scan_info = {}

        # Parse all the <scaninfo> elements
        for element in self._xml_tree.findall('.//scaninfo'):
            
            current_scan_tag_attributes = element.attrib
            scan_info[current_scan_tag_attributes['protocol']] = {
                'type': current_scan_tag_attributes['type'],
                'numservices': current_scan_tag_attributes['numservices'],
                'services': current_scan_tag_attributes['services']
            }

        general_info['scan_info'] = scan_info

        # Parse the <verbose> and <debugging> tags if they exist
        verb_elem = self._xml_tree.find('.//verbose')
        if verb_elem is not None:
            general_info['verbose'] = verb_elem.attrib['level']

        debug_elem = self._xml_tree.find('.//debugging')
        if debug_elem is not None:
            general_info['debug'] = debug_elem.attrib['level']

        scan_result = NmapScanResult(**general_info)

        # Loop through every <host> element, which contains very host scan result.
        for host in self._xml_tree.findall('.//host'):
            host_info = {
                'start_time': host.attrib['starttime'],
                'end_time': host.attrib['endtime']
            }
            status_element = host.find('status')
            if status_element is None:
                raise XMLParsingError('Could not get status from host')
            host_info['state'] = status_element.attrib['state'] 
            host_info['reason'] = status_element.attrib['reason'] 
            host_info['reason_ttl'] = status_element.attrib['reason_ttl'] 
            address_items = host.findall('.//address')
            if not address_items:
                raise XMLParsingError('Could not be able to parse host address')
            
            # Parse IPv4 and IPv6 if exist
            for addr in address_items:
                if addr.attrib['addrtype'] == 'ipv4':
                    host_info['ipv4'] = addr.attrib['addr']
                elif addr.attrib['addrtype'] == 'ipv6':
                    host_info['ipv6'] = addr.attrib['addr']
            
            if 'ipv4' not in host_info and 'ipv6' not in host_info:
                raise XMLParsingError('Cannot parse host that no IPv4 nor IPv6 address')

            # Parse hostnames
            hostnames_element = host.find('hostnames')
            if hostnames_element is not None:
                host_info['hostnames'] = {}
                for hostname_element in hostnames_element:
                    host_info['hostnames'][hostname_element.attrib['name']] = hostname_element.attrib['type']

            # Get OS fingerprint
            os_fingerprint_element = host.find('.//osfingerprint')
            if os_fingerprint_element is not None:
                host_info['fingerprint'] = os_fingerprint_element.attrib['fingerprint']

            # Instatiate the host
            host_instance = Host(**host_info)

            # Parse all ports
            scan_info = host.find('ports')
            if scan_info is not None:
                for port in scan_info.findall('port'):
                    port_info = {
                        'protocol': port.attrib['protocol'],
                        'number': port.attrib['portid']
                    }
                    
                    state_element = port.find('state')
                    if state_element is None:
                        raise XMLParsingError('Cannot find state element from port')
                    port_info['state'] = state_element.attrib['state']
                    port_info['reason'] = state_element.attrib['reason']
                    port_info['reason_ttl'] = state_element.attrib['reason_ttl']

                    # Create the port object
                    port_instance = Port(**port_info)

                    # Parse service information
                    service_info = {'port': port_info['number']}
                    service_element = port.find('service')
                    if service_element is not None:
                        service_info['name'] = service_element.attrib['name']
                        try:
                            service_info['product'] = service_element.attrib['product']
                        except KeyError:
                            service_info['product'] = None
                        try:
                            service_info['version'] = service_element.attrib['version']
                        except KeyError:
                            service_info['version'] = None
                        try:
                            service_info['extrainfo'] = service_element.attrib['extrainfo']
                        except KeyError:
                            service_info['extrainfo'] = None
                        try:
                            service_info['tunnel'] = service_element.attrib['tunnel']
                        except KeyError:
                            service_info['tunnel'] = None
                        try:
                            service_info['method'] = service_element.attrib['method']
                        except KeyError:
                            service_info['method'] = None
                        try:
                            service_info['conf'] = service_element.attrib['conf']
                        except KeyError:
                            service_info['conf'] = None
                        
                        service_info['cpes'] = []

                        # Get CPEs
                        for cpe_item in service_element.findall('cpe'):
                            service_info['cpes'].append(cpe_item.text)

                        # Bind the service instance with the port instance
                        service_instance = Service(**service_info)

                        for script in port.findall('script'):
                            service_instance._add_script(script.attrib['id'], script.attrib['output'])

                        port_instance._add_service(service_instance)

                    # Bind the port instance to the current host
                    host_instance._add_port(port_instance)

            os_root_element = host.find('os')

            # Add OS information
            if os_root_element is not None:

                for os_element in os_root_element.findall('osmatch'):
                    os_info = {}
                    os_info['name'] = os_element.attrib['name']
                    os_info['accuracy'] = os_element.attrib['accuracy']
                    matches = []
                    for os_match_element in os_element.findall('osclass'):
                        match_info = {}
                        for attrib_name in ('type', 'vendor', 'family', 'generation'):
                            try:
                                match_info[attrib_name] = os_match_element.attrib[attrib_name]
                            except KeyError:
                                match_info[attrib_name] = None
                        
                        match_info['cpe'] = None

                        cpe_element = os_match_element.find('cpe')
                        if cpe_element is not None:
                            match_info['cpe'] = cpe_element.text
                        
                        matches.append(match_info)
                    
                    os_info['matches'] = matches
                    os_instance = OperatingSystem(**os_info)
                    host_instance._add_os(os_instance) 
            
            # Parse traceroute
            trace_element = host.find('trace')
            if trace_element is not None:
                hops = []
                for hop in trace_element.findall('hop'):
                    hop_info = {}
                    try:
                        hop_info['host'] = hop.attrib['host']
                    except KeyError:
                        hop_info['host'] = None
                    try:
                        hop_info['ttl'] = hop.attrib['ttl']
                    except KeyError:
                        hop_info['ttl'] = None
                    try:
                        hop_info['rtt'] = hop.attrib['rtt']
                    except KeyError:
                        hop_info['rtt'] = None
                    try:
                        hop_info['ip'] = hop.attrib['ipaddr']
                    except KeyError:
                        hop_info['ip'] = None

                    hops.append(Hop(**hop_info))
                
                host_instance._add_hops(*hops)

            # Parse host scripts
            hostscript_element = host.find('hostscript')
            if hostscript_element:
                for script_element in hostscript_element.findall('script'):
                    host_instance._add_script(script_element.attrib['id'], script_element.attrib['output'])

            scan_result._add_hosts(host_instance)

        return scan_result
        