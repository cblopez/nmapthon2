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

from ._results import NmapScanResult

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

    def parse_file(self, file_path: str, as_boolean: bool = False):
        """ Parse a XML file in the system.

        :param file_path: Path from the file as a String or a Path object.
        :param as_boolean: If True, the method will return True if file is found and parsed
                           successfully, but False in any other case. If False, the common 
                           FileNotFoundError exception will be raised.
        :raises FileNotFoundError: If file is not found and as_boolean is False.
        :returns: Parsed file as NmapScanResult.
        """

        if isinstance(file_path, pathlib.Path):
            file_path = file_path.absolute
        try:
            with open(file_path) as f:
                return self._parse(f.read())
        except FileNotFoundError:
            if as_boolean:
                return False
            else:
                raise

        return True

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

        self._xml_tree = ET.fromstring(text)

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
            elif attribute == 'time':
                general_info['hosts_down'] = value
            elif attribute == 'time':
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

        
            