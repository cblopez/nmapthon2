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


# This module defines async operations for Nmap scans

import pathlib
import random
import os
import subprocess
import string

from typing import Union, Iterable, Tuple

from .scanner import NmapScanner
from .results import NmapScanResult
from .exceptions import NmapScanError, XMLParsingError
from .engine import NSE
from .ports import _PortAbstraction
from .status import Status


class NmapAsyncScanner(NmapScanner):
    """ Allows async operations for Nmap scans, like background execution, status retrieval and process awaiting
    
    It works like the NmapScanner object but has some additional methods and kwargs on its methods. The class overrides some of the core 
    NmapScanner functionality in order allow the manipulation of the Nmap's child process.
    """

    def __init__(self, nmap_bin: Union[None,str] = None, engine: Union[None,NSE] = None):
        super().__init__(nmap_bin, engine)
        self._nmap_process = None
        self._has_started = False
        self._has_awaited = False

        self._stored_output_buffer = None
        self._stored_error_buffer = None

        # Flags to check execution type
        self._requires_file_parsing = False
        self._xml_file_path = None

        # Save any needed information to be used across multiple methods
        self._priority_engine = None
        self._output_base_filename = None

        # Status flags
        self._with_status = False
        self._retrieved_status = False
        self._last_status_instance = None

    @property
    def _selected_engine(self):
        if self._priority_engine:
            return self._priority_engine
        else:
            return self._engine

    def _add_stats_every(self, command, interval) -> str:
        """ Extends a Nmap command with the --stats-every agument
        
        :param command: Command to extend
        :param interval: Stats every interval
        """
        nmap_command_length = 4 if not self._nmap_bin else len(self._nmap_bin)

        return fr'{command[:nmap_command_length]} --stats-every {interval}{command[nmap_command_length:]}'


    def _execute_nmap(self, nmap_arguments) -> Tuple[bytes,bytes]:
        """ Execute and asynchronous Nmap process

        :param nmap_arguments: List of Nmap arguments
        :raises NmapScanError: If the provided Nmap binary path is not valid.
        """

        # Popen raises FileNotFoundError in case the program does not exist
        try:
            self._has_started = True
            self._nmap_process = subprocess.Popen(nmap_arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            raise NmapScanError('Nmap was not found on the system. Please install it before using Nmapthon2') from None

    def scan(self, targets: Union[str,Iterable], ports: Union[None,int,str,Iterable,_PortAbstraction] = None,  arguments: Union[None,str] = None, 
             dry_run: bool = False, output: Union[None,str,Iterable] = None, engine: Union[None,NSE] = None, with_status: bool = False, status_interval: str = '3s'):
        """ Execute an Nmap scan based on on a series of targets, and optional ports and
        arguments. For multi-output format storage the output argument can be set with 
        the needed extersions or output parameters. It also accepts an NSE engine that will override the instance`s engine, in case there is one.
        It works with asynchronous operations.

        :param targets: Targets to scan inside a str or Iterable type, like a list. Targets can also be specified through network ranges, partial ranges, network with CIDR mask and domains/hostnames.
        :param ports: Ports to scan in as an int, str, iterable or custom functions. Ports can also be specified with ranges.
        :param arguments: Arguments to execute Nmap in a single string
        :param dry_run: Set to True if you just want to test your parameters, with this option the scan does NOT run.     
        :param output: Iterable with desired output formats, that can be "xml", "normal" and/or "grep".
        :param engine: NSE object for custom script execution. It overrides the NSE object specified on the instance for the current scan.
        :param with_status: If set to True, it appends status information to the Nmap output every status_interval. Defalt: False
        :param status_interval: Status interval to STDOUT in Nmap-like format. Default: '5s'
        :raises NmapScanError: If you call scan() on an instance that is already scanning
        """

        if self._has_started:
            raise NmapScanError('Cannot call scan() on an instance that is already scanning')

        # Set priority engine and started flag
        self._has_started = True
        if engine:
            self._priority_engine = engine

        random_nmap_output_filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(25))
        nmap_command = self._create_nmap_command(targets, random_nmap_output_filename, ports, arguments, output)

        # If dry_run, do not execute
        if dry_run:
            return

        # If with_status, add to command
        if with_status:
            self._with_status = True
            self._stored_output_buffer = ''
            nmap_command = self._add_stats_every(nmap_command, status_interval)

        # Store output base filename if output was specified, and say that it needs file processing
        if output:
            self._requires_file_parsing = True
            self._xml_file_path = os.path.join(self._temp_folder, f'{random_nmap_output_filename}.xml')
            self._output_base_filename = random_nmap_output_filename

        self._execute_nmap(nmap_command)

    def raw(self, raw_arguments: str, engine: Union[None,NSE] = None):
        """ Executes a Nmap scan with a raw string containing all the command itself, without the 'nmap' keyword, but with asynchronous opeartions

        :param raw_arguments: String containing all nmap arguments. No --resume option nor output options should be placed here.
        :param engine: NSE instance to use for this particular scan.
        :raises NmapScanError: If raw() is called on an instance that is already scanning
        """

        if self._has_started:
            raise NmapScanError('Cannot call raw() on a instance that is already scanning')

        # Set priority engine and started flag
        self._has_started = True
        if engine:
            self._priority_engine = engine

        if raw_arguments.startswith('nmap '):
            raw_arguments = raw_arguments[5:]
        
        if any([x in raw_arguments for x in ('--resume', '-oA', '-oX', '-oN', '-oS', '-oG')]):
            raise NmapScanError('Cannot specify --resume nor output options.')
        
        if self._nmap_bin:
            nmap_bin = self._nmap_bin
        else:
            nmap_bin = 'nmap'
        
        raw_arguments = '{} {} -oX -'.format(nmap_bin, raw_arguments)
        
        self._execute_nmap(self._split_command(raw_arguments))

    def resume(self, xml_file: Union[pathlib.Path,str]):
        """ Resumes an Nmap scan from an XML file, but with asynchronous operations

        :param xml_file: String representing the file's path
        :raises NmapScanError: If you call resume on an instance that has already started a scan
        """
        if self._has_started:
            raise NmapScanError('Cannot call resume() on an instance that is already scanning')
        
        # Set the resume and has_started flag
        self._requires_file_parsing = True
        self._has_started = True

        if isinstance(xml_file, pathlib.Path):
            xml_file = xml_file.absolute

        # Set to instance attribute for later processing
        self._xml_file_path = xml_file

        if self._nmap_bin:
            nmap_bin = self._nmap_bin
        else:
            nmap_bin = 'nmap'

        self._execute_nmap(self._split_command('{} --resume {}'.format(nmap_bin, xml_file)))
            
    def get_result(self) -> Union[None,NmapScanResult]:
        """ Returns the NmapScanResult object from the performed scan and raises any non-tolerant errors return by Nmap, if any.
        
        :raises NmapScanError: When trying to get hte result from a scan that has not started
        :returns: Scan result
        """

        if not self._has_started:
            raise NmapScanError('Cannot get a result from a scan that has not started')

        # If blocking, just let the function continue, since the communicate() call will freeze the thread
        if not self.finished():
            return None
        
        # Check what buffers to use, the already stored ones or the processes pipes
        # Also, check if status has been retrieved, since buffers may need to be concatenated, as the operating system flushes
        # the processes stdout every team we read a 256 chunk.
        if self._has_awaited:
            output_buff, err_buff = self._stored_output_buffer, self._stored_error_buffer
        elif self._retrieved_status:
            output_buff = self._stored_output_buffer + self._nmap_process.stdout.read().decode('latin-1')
            err_buff = self._nmap_process.stderr.read().decode('latin-1')
        else:
            output_buff, err_buff = self._nmap_process.communicate()

        try:
            # If resume(), parse the stored XML file in the instance attribute
            if self._requires_file_parsing:
                if not err_buff:
                    with open(self._xml_file_path) as f:
                        return self._parse_nmap_output(output_buff, err_buff, output=self._output_base_filename, engine=self._priority_engine)
                else:
                    raise NmapScanError(err_buff.decode('utf8'))
            else:
                return self._parse_nmap_output(output_buff, err_buff, output=self._output_base_filename, engine=self._priority_engine)
        finally:
            # Reset values for the next scan
            if self._output_base_filename:
                self._delete_output_files(self._output_base_filename)

    def finished(self) -> bool:
        """ Returns True or False depending on whether the Nmap process has ended or not
        
        :raises NmapScanError: If no scan has been started
        """
        if not self._has_started:
            raise NmapScanError('Cannot check if a scan has finished without starting it')

        return self._nmap_process.poll() is not None
    
    def wait(self):
        """ Freezes the main process until Nmap finishes

        :raises NmapScanError: If no scan has been started
        """
        if not self._has_started:
            raise NmapScanError('Cannot wait on a scan that has not started')

        # Set the has_awaited flag to True, which will cause the get_result method to return the result based on the already stored buffers
        self._has_awaited = True
        temp_output_buffer, self._stored_error_buffer = self._nmap_process.communicate()

        if self._retrieved_status:
            self._stored_output_buffer += temp_output_buffer.decode('latin-1')
        else:
            self._stored_output_buffer = temp_output_buffer

    def get_status(self) -> Union[None,Status]:
        """ Return a Status object representing Nmap's status. It returns None if no status could be parsed yet.

        :returns: Status representing Nmap's status
        :raises NmapScanError: If get_status() is called without previously setting with_status=True in the scan() method
        """
        if not self._with_status:
            raise NmapScanError('Cannot get Nmap status without setting with_status.')
        
        self._retrieved_status = True

        # If Nmap is writing its output to a file, then read the file instead of reading the process buffer
        # Catch FileNotFoundError to control race conditions with Nmap's child process
        if self._requires_file_parsing:
            try:
                with open(self._xml_file_path) as f:
                    return Status.from_raw_xml(f.read())
            except FileNotFoundError:
                return None

        # In any other case, just append to buffer
        else:
            line = self._nmap_process.stdout.read(256).decode('latin-1')
            if line:
                self._stored_output_buffer += line
            
            return Status.from_raw_xml(self._stored_output_buffer)

    def reset(self):
        """ Reset all the flags and scan-related variables to its original value
        """
        self._output_base_filename = None
        self._priority_engine = None
        self._stored_output_buffer = None
        self._stored_error_buffer = None
        self._has_started = False
        self._has_awaited = False
        self._requires_file_parsing = False
        self._xml_file_path = None
        self._with_status = False
        self._retrieved_status = False
        self._last_status_instance = None