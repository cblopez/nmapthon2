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
import shlex
import tempfile
import subprocess
import random
import string
import os

from collections.abc import Iterable
from typing import Coroutine, Tuple, Union
import nmapthon2

from nmapthon2.results import NmapScanResult

from .parser import XMLParser
from .exceptions import InvalidArgumentError, NmapScanError, XMLParsingError
from .ports import _PortAbstraction
from .engine import NSE


OUTPUT_FORMATS = ('all', 'xml', 'normal', 'grep')
OUTPUT_RELATION = {
    'xml': '.xml',
    'normal': '.nmap',
    'grep': '.gnmap'
}


class NmapScanner:
    """ Represents a reusable Nmap Network scanner that wraps the results into
    NmapScanResult objects.

    It offers several methods to execute Nmap scans by different means, which are: 
    1) Specify targets, ports and arguments in three different arguments. 2) Specify the raw Nmap command. 
    3) Resume an Nmap scan

    Nmap does not allow multi format output to STDOUT, so this class may write to 
    the operating system temporal folder to write all the output formats, process them, and 
    delete them.

    :param nmap_bin: Path to the binary Nmap file.
    :param engine: Default NSE object for all scans performed with this scanner.
    """

    def __init__(self, nmap_bin: Union[None,str] = None, engine: Union[None,NSE] = None):

        self._temp_folder = tempfile.gettempdir()
        self._xml_parser = XMLParser()

        assert nmap_bin is None or isinstance(nmap_bin, str), 'nmap_bin must be None or str'
        assert engine is None or isinstance(engine, NSE), 'engine must be None or an instance of NSE'
        self._nmap_bin = nmap_bin
        self._engine = engine

    @staticmethod
    def _split_command(command: str) -> Union[list,str]:
        """ Split a command into a list of strings in UNIX systems, but leave the command as a single string for Windows systems.
        
        Commands including paths with Windows delimeters (\) will be missprocessed, causing errors in Windows systems. Nonetheless, 
        Windows systems do not require an array of arguments like UNIX, so passing the raw command is completely fine.

        :param command: Command to process
        """

        if os.name == 'nt':
            return command
        else:
            return shlex.split(command)

    def _parse_command_line_arguments(self, arguments_string):
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
        split_arguments = self._split_command(arguments_string)

        if '--resume' in split_arguments:
            raise NmapScanError('Cannot use --resume as a Nmap argument. Use resume() instead')

        if '-oX' in split_arguments or '-oN' in split_arguments or \
            '-oA' in split_arguments or '-oG' in split_arguments or '-oS' in split_arguments:
            raise NmapScanError('Cannot especify an output argument. Use the "output" kwarg instead.')

        if isinstance(split_arguments, list):
            return ' '.join(split_arguments)
        else:
            return split_arguments
    
    @staticmethod
    def _parse_output_flag(output):
        """ Parses the output wkarg from the scan() method.
        
        :returns: Iterable with output options correctly parsed.
        """

        # If str
        if isinstance(output, str):
            if output == 'kiddie':
                raise InvalidArgumentError('You should not be using this library, young padawan.')

            if output not in OUTPUT_FORMATS:
                raise InvalidArgumentError('Scan output must be of a valid type: {}'.format(', '.join(OUTPUT_FORMATS)))
                
            # Set the output to all other options if "all" is specified
            if output == 'all':
                return OUTPUT_FORMATS[1:]
            else:
                return (output,)

        # If iterable, validate them and change the variable to each type if "all" is specified
        elif isinstance(output, Iterable):
            if 'kiddie' in output:
                raise InvalidArgumentError('You should not be using this library, young padawan.')

            if 'all' in output:
                return OUTPUT_FORMATS[1:]

            else:
                for i in output:
                    if i not in OUTPUT_FORMATS:
                        raise InvalidArgumentError('Invalid output value: {}'.format(i))
            
            return output

        # Raise error in any other case
        else:
            raise TypeError('output parameter must be a string or an iterable with valid format types')

    @staticmethod
    def _parse_ports_flag(ports):
        """ Parses the ports flag from the scan() method
        
        :returns: Parsed string
        """

        if isinstance(ports, (str, int)) or isinstance(ports, Iterable):
            return _PortAbstraction()._malleable(ports).to_nmap_syntax()
        elif isinstance(ports, _PortAbstraction):
            return ports.to_nmap_syntax()
        else:
            raise InvalidArgumentError('Invalid type for ports. Expecting str, Iterable or specific function calling, but got: {}'.format(type(ports)))

    def _parse_targets(self, targets):
        """ Parses the targets from the scan() method
        
        :returns: Parsed targets
        """

        if isinstance(targets, str):
            if ' nmapthon ' in targets:
                raise NmapScanError('You dare to scan me?')
            _ = self._split_command(targets)
            return targets
        elif isinstance(targets, Iterable):
            if 'nmapthon' in targets:
                raise NmapScanError('You dare to scan me?')
            targets_str = ' '.join(targets)
            _ = self._split_command(targets_str)
            return targets_str
        else:
            raise InvalidArgumentError('Invalid targets type, expected str or Iterable, but got {}'.format(type(targets)))

    def _delete_output_files(self, random_nmap_output_filename):
        """ Deletes all generated files from Nmap
        
        :param random_nmap_output_filename: Random string to be used for file generation
        """
        for i in ('.xml', '.gnmap', '.nmap'):
            try:
                os.remove(os.path.join(self._temp_folder, random_nmap_output_filename, i))
            except FileNotFoundError:
                pass

    def _execute_nmap(self, nmap_arguments) -> Tuple[bytes,bytes]:
        """ Execute nmap and return the STDOUT and STDERR from the child process created

        :param nmap_arguments: List of Nmap arguments
        :raises NmapScanError: If the provided Nmap binary path is not valid.
        """

        # Popen raises FileNotFoundError in case the program does not exist
        try:
            nmap_process = subprocess.Popen(nmap_arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except FileNotFoundError:
            raise NmapScanError('Nmap was not found on the system. Please install it before using Nmapthon2') from None

        return nmap_process.communicate()

    def _create_nmap_command(self, targets, random_nmap_base_filename, ports, arguments, output) -> list:
        """ Execute an Nmap scan based on on a series of targets, and optional ports and
        arguments. For multi-output format storage the output argument can be set with 
        the needed extersions or output parameters.

        :param targets: List of targets in an Iterable or str.
        :param random_nmap_base_filename: Random Nmap filename to create output files
        :param ports: Ports in str or list format
        :param arguments: Arguments to execute within the scan.
        :param output: Tuple or list of output formats.
        """

        # Validate, parse parameters and add them to the command
        
        # Target parsing
        targets = self._parse_targets(targets)

        # Add the commands
        if self._nmap_bin:
            nmap_command = self._nmap_bin
        else:
            nmap_command = 'nmap '

        # Ports
        if ports:
            ports = self._parse_ports_flag(ports)
            if '--top-ports' in ports:
                nmap_command += '{} '.format(ports)
            else:
                nmap_command += '-p{} '.format(ports)
        
        # Arguments
        if arguments:
            arguments = self._parse_command_line_arguments(arguments)
            nmap_command += '{} '.format(arguments)
        
        # Depending on the output argument, should add '-oX -' or start handling output through temp files.
        if output:
            output = self._parse_output_flag(output)
            nmap_command += '-oA {} '.format(os.path.join(self._temp_folder, random_nmap_base_filename))
        else:
            nmap_command += '-oX - '

        nmap_command += targets

        return self._split_command(nmap_command)

    def _parse_nmap_output(self, exec_output, exec_error, output: Union[None,str] = None, engine: Union[None,NSE] = None, skip_processing: bool = False) -> NmapScanResult:
        """ Parses the Nmap output comming from its execution through the child process, performs any required validations 
        and cleans the filesystem in case any files were created.

        :param exec_output: Child process' STDOUT
        :param exec_error: Child process' STDERR
        :param output: Single value representing the random filename assigned to the created files by the output flag
        :param engine: NSE object to execute after the scan
        :param skip_processing: Set to true, it does not try to process Nmap output. Should be used when resumming.
        """
        if len(exec_output):
            
            # If no output was set, parse directly from output
            if output is None:
                try:
                    result = self._xml_parser.parse_plain(exec_output)
                except XMLParsingError as e:
                    if isinstance(exec_error, bytes):
                        raise NmapScanError(exec_error.decode('utf8'))
                    else:
                        raise NmapScanError(exec_error)
            
                if skip_processing:
                    return None

            # If output was set, parse it from XML output file.
            else:
                try:
                    result = self._xml_parser.parse_file(os.path.join(self._temp_folder, '{}.xml'.format(output)))
                except XMLParsingError:
                    if isinstance(exec_error, bytes):
                        raise NmapScanError(exec_error.decode('utf8'))
                    else:
                        raise NmapScanError(exec_error)
                
                outputs = { 'xml': None, 'normal': None, 'grep': None }
                for i in outputs:
                    with open(os.path.join(self._temp_folder, '{}{}'.format(output, OUTPUT_RELATION[i]))) as f:
                        outputs[i] = f.read()
                
                result._normal_output = outputs['normal']
                result._grep_output = outputs['grep']
                result._xml_output = outputs['xml']

            # If execution reaches this point, then Nmapthon2 has parsed the XML correctly, but they might be tolerant errors remaining
            if len(exec_error):
                result.tolerant_errors = exec_error.decode('utf8')

            # Reference the coorect engine instance
            if not engine:
                engine = self._engine

            # Apply the engine parser and scripts execution to the Host, Port and Service instances
            if engine:
                for host in result:
                    # Apply any host script to the host object by reference
                    engine._apply_host_scripts(host)
                    for port in host:
                        # If any parser to be used and there is a service with optential scripts, rock'em
                        if len(engine._parsers) and port.service:
                            for script_name, callback in engine._parsers.items():
                                try:
                                    port.service._scripts[script_name] = callback(port.service._scripts[script_name])
                                except KeyError as e:
                                    # If the KeyError is because of the script key not being in _scripts, then thats ok
                                    # but if not, should raise the exception to let know the programmer.
                                    if "'{}'".format(script_name) == str(e):
                                        pass
                                    else:
                                        raise
                        
                        # If any port script, apply it
                        engine._apply_port_scripts(host, port, port.service)

            return result
        
        else:
            if not skip_processing:
                if isinstance(exec_error, bytes):
                    raise NmapScanError(exec_error.decode('utf8'))
                else:
                    raise NmapScanError(exec_error)
    
    def scan(self, targets: Union[str,Iterable], ports: Union[None,int,str,Iterable,_PortAbstraction] = None,  arguments: Union[None,str] = None, 
             dry_run: bool = False, output: Union[None,str,Iterable] = None, engine: Union[None,NSE] = None) -> NmapScanResult:
        """ Execute an Nmap scan based on on a series of targets, and optional ports and
        arguments. For multi-output format storage the output argument can be set with 
        the needed extersions or output parameters. It also accepts an NSE engine that will override the instance`s engine, in case there is one.

        :param targets: Targets to scan inside a str or Iterable type, like a list. Targets can also be specified through network ranges, partial ranges, network with CIDR mask and domains/hostnames.
        :param ports: Ports to scan in as an int, str, iterable or custom functions. Ports can also be specified with ranges.
        :param arguments: Arguments to execute Nmap in a single string
        :param dry_run: Set to True if you just want to test your parameters, with this option the scan does NOT run.     
        :param output: Iterable with desired output formats, that can be "xml", "normal" and/or "grep".
        :param engine: NSE object for custom script execution. It overrides the NSE object specified on the instance for the current scan.
        """

        if output:
            random_nmap_output_filename = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(25))
        else:
            random_nmap_output_filename = None

        nmap_command = self._create_nmap_command(targets, random_nmap_output_filename, ports, arguments, output)

        # If dry_run, do not execute
        if dry_run:
            return None

        try:
            output_buff, error_buff = self._execute_nmap(nmap_command)
            return self._parse_nmap_output(output_buff, error_buff, output=random_nmap_output_filename, engine=engine)
        finally:
            if output:
                self._delete_output_files(random_nmap_output_filename)
        

    def raw(self, raw_arguments: str, engine: Union[None,NSE] = None) -> NmapScanResult:
        """ Executes a Nmap scan with a raw string containing all the command itself, without the 'nmap' keyword.

        :param raw_arguments: String containing all nmap arguments. No --resume option nor output options should be placed here.
        :param engine: NSE instance to use for this particular scan.
        """

        if raw_arguments.startswith('nmap '):
            raw_arguments = raw_arguments[5:]
        
        if any([x in raw_arguments for x in ('--resume', '-oA', '-oX', '-oN', '-oS', '-oG')]):
            raise NmapScanError('Cannot specify --resume nor output options.')
        
        if self._nmap_bin:
            nmap_bin = self._nmap_bin
        else:
            nmap_bin = 'nmap'
        
        raw_arguments = '{} {} -oX -'.format(nmap_bin, raw_arguments)
        
        output_buff, error_buff = self._execute_nmap(self._split_command(raw_arguments))
        return self._parse_nmap_output(output_buff, error_buff, engine=engine)

    def resume(self, xml_file: Union[pathlib.Path,str]) -> NmapScanResult:
        """ Resumes an Nmap scan from an XML file.

        :param xml_file: String representing the file's path
        """

        if isinstance(xml_file, pathlib.Path):
            xml_file = xml_file.absolute

        if self._nmap_bin:
            nmap_bin = self._nmap_bin
        else:
            nmap_bin = 'nmap'

        _, error_buff = self._execute_nmap(self._split_command('{} --resume {}'.format(nmap_bin, xml_file)))

        # Resume should not be checked through output_buff, since a --resume command may not any output at all.
        if not error_buff:
            return self._xml_parser.parse_file(xml_file)
        else:
            if isinstance(error_buff, bytes):
                raise NmapScanError(error_buff.decode('utf8'))
            else:
                raise NmapScanError(error_buff)

    def from_file(self, xml_file: Union[pathlib.Path,str], **kwargs) -> NmapScanResult:
        """ Imports an existing XML file and returns a scan result
        
        :param xml_file: String representing the file's path
        """

        return self._xml_parser.parse_file(xml_file, **kwargs)

    def from_str(self, plain_output: str) -> NmapScanResult:
        """ Directly parse a string containing the Nmap output
        
        :param plain_output: String containing the Nmap output
        """

        return self._xml_parser.parse_plain(plain_output)