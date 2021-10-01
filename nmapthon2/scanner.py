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

import shlex
import tempfile
import subprocess

import utils

from collections.abc import Iterable

from .parser import XMLParser
from .exceptions import NmapScanError
from . import utils


OUTPUT_FORMATS = ('all', 'xml', 'normal', 'grep')


class NmapScanner:
    """ Represents a re-usable Nmap Network scanner that wraps the results into
    NmapScanResult objects.

    It offers several methods to execute Nmap scans by different means, which are:
    - Specify targets, ports and arguments in three different arguments
    - Specify the raw Nmap command
    - Resume an Nmap scan

    Nmap does not allow multi format output to STDOUT, so there this class may write to 
    the operating system temporal folder to write all the output formats, process them, and 
    delete them.

    Attributes:
        _temp_folder: Temporal folder from the current OS
        _xml_parser: Parser for Nmap scan results
    """

    def __init__(self):
        self._temp_folder = tempfile.gettempdir()
        self._xml_parser = XMLParser()

    @staticmethod
    def _parse_command_line_arguments(arguments_string):
        """ Parse the command line arguments from a given arguments string.

        Arguments have a few restrictions, which are: 1) the "nmap" command itself
        is added by Nmapthon2, so the arguments command must not start with it. 2) No
        output command should be passed (-oA, -oN, -oG, -oX or -oS), since by default 
        -oX - will be used, and in case user needs multi-output it is needed to use
        the output kwarg through the scan() method. 3) No --resume option should be used,
        the resume() method must be called instead.

        :param arguments_string: Raw arguments string.
        """

        # Split into a list of commands
        split_arguments = shlex.split(arguments_string)

        if '--resume' in split_arguments:
            raise NmapScanError('Cannot use --resume as a Nmap argument. Use resume() instead')

        if '-oX' in split_arguments or '-oN' in split_arguments or \
            '-oA' in split_arguments or '-oG' in split_arguments or '-oS' in split_arguments:
            raise NmapScanError('Cannot especify an output argument.')

        return split_arguments
    
    def scan(self, targets, ports=None, arguments=None, output=None):
        """ Execute an Nmap scan based on on a series of targets, and optional ports and
        arguments. For multi-output format storage the output argument can be set with 
        the needed extersions or output parameters.

        :param targets: List of targets in an Iterable or str.
        :param ports: Ports in str or list format
        :param arguments: Arguments to execute within the scan.
        :param output: Tuple or list of output formats.
        """

        # Validate parameters
        if output:
            if not isinstance(output, Iterable):
                raise TypeError('output parameter must be an iterable with valid format types')
        
        for i in output:
            if i not in OUTPUT_FORMATS:
                raise TypeError('Invalid output type: {}. Valid types are {}'.format(i, ','.join("'{}'".format(x) for x in OUTPUT_FORMATS)))
        
        