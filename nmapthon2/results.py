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

import datetime
from typing import Union

from . import utils
from .elements import Host


OUTPUT_FORMATS = ['normal', 'grep', 'xml']

class NmapScanResult:
    """ An instance of this class encapsulates the output of a Nmap
    execution.

    Scan results have several parts that should be distinguished. First,
    it contains overall scan information, which includes the time spent,
    nmap version, arguments that have been executed, etc...

    Then, the results have information from the scanned hosts, including
    general information from the host: IP Address, hostnames, scanned ports, services
    inside those ports... As well as scripts. These scripts can be host-oriented
    which are, indeed, binded to the host, and service-oriented, which are binded to
    the services.

    Additionally, these hosts could also have Operating System results and NSE
    results, which are unique from this library.
    """

    __slots__ = ('_scanner', '_arguments', '_start_timestamp', '_start_datetime',
                 '_version', '_end_timestamp', '_end_datetime', '_elapsed', '_summary',
                 '_exit_status', '_hosts_up', '_hosts_down', '_num_hosts', '_scan_info',
                 '_verbose', '_debug', '_hosts', '_tolerant_errors', '_xml_output', 
                 '_grep_output', '_normal_output', '_index')

    def __init__(self, **kwargs):
        self.scanner = kwargs.get('scanner', None)
        self.arguments = kwargs.get('arguments', None)
        self.start_timestamp = kwargs.get('start_timestamp', None)
        self.start_datetime = kwargs.get('start_datetime', None)
        self.version = kwargs.get('version', None)
        self.end_timestamp = kwargs.get('end_timestamp', None)
        self.end_datetime = kwargs.get('end_datetime', None)
        self.elapsed = kwargs.get('elapsed', None)
        self.summary = kwargs.get('summary', None)
        self.exit_status = kwargs.get('exit_status', None)

        self._hosts_up = kwargs.get('hosts_up', None)
        self._hosts_down = kwargs.get('hosts_down', None)
        self._num_hosts = kwargs.get('num_hosts', None)
    
        self.scan_info = kwargs.get('scan_info', None)
        self.verbose = kwargs.get('verbose', None)
        self.debug = kwargs.get('debug', None)

        self.tolerant_errors = None
        
        self._hosts = []

        self._xml_output = None
        self._grep_output = None
        self._normal_output = None

        self._index = -1

    @property
    def scanner(self) -> Union[None,str]:
        """ Nmap scanner information
        """
        return self._scanner
    
    @scanner.setter
    def scanner(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.scanner must be None or str'

        self._scanner = v
    
    @property
    def arguments(self) -> Union[None,str]:
        """ Command-line arguments used
        """
        return self._arguments
    
    @arguments.setter
    def arguments(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.arguments must be None or str'

        self._arguments = v

    @property
    def start_timestamp(self) -> Union[None,int]:
        """ Start time timestamp
        """
        return self._start_timestamp
    
    @start_timestamp.setter
    def start_timestamp(self, v):
        assert v is None or isinstance(v, str) or isinstance(v, int), 'NmapScanResult.start_timestamp must be None, str or int'

        if v is not None:
            self._start_timestamp = int(v)
        else:
            self._start_timestamp = v   
    
    @property
    def start_datetime(self) -> Union[None,datetime.datetime]:
        """ Start time datetime object
        """
        return self._start_datetime
    
    @start_datetime.setter
    def start_datetime(self, v):
        
        if v is not None:
            self._start_datetime = datetime.datetime.fromtimestamp(int(v))
        else:
            self._start_datetime = None

    @property
    def version(self) -> Union[None,str]:
        """ Get Nmap version
        """
        return self._version
    
    @version.setter
    def version(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.start_timestamp must be None or str'

        self._version = v

    @property
    def end_timestamp(self) -> Union[None,int]:
        """ End time timestamp
        """
        return self._end_timestamp
    
    @end_timestamp.setter
    def end_timestamp(self, v):
        assert v is None or isinstance(v, (str, int)), 'NmapScanResult.end_timestamp must be None, str or int'

        if v is not None:
            self._end_timestamp = int(v)
        else:
            self._end_timestamp = v
    
    @property
    def end_datetime(self) -> Union[None,datetime.datetime]:
        """ End time datetime object
        """
        return self._end_datetime
    
    @end_datetime.setter
    def end_datetime(self, v):
        if v is not None:
            self._end_datetime = datetime.datetime.fromtimestamp(int(v))
        else:
            self._end_datetime = None

    @property
    def elapsed(self) -> Union[None,float]:
        """ Elapsed time
        """
        return self._elapsed
    
    @elapsed.setter
    def elapsed(self, v):
        assert v is None or isinstance(v, str) or isinstance(v, float), 'NmapScanResult.elapsed must be None, str or float'
        try:
            self._elapsed = float(v)
        except ValueError:
            pass
    
    @property
    def summary(self) -> Union[None,str]:
        """Scan summary
        """
        return self._summary
    
    @summary.setter
    def summary(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.summary must be None or str'
        
        self._summary = v
    
    @property
    def exit_status(self) -> Union[None,str]:
        """ Nmap exit status
        """
        return self._exit_status
    
    @exit_status.setter
    def exit_status(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.exit_status must be None or str'
        
        self._exit_status = v

    @property
    def hosts_up(self) -> Union[None,int]:
        """ Number of hosts up
        """
        return self._hosts_up
    
    @property
    def hosts_down(self) -> Union[None,int]:
        """ Number of hosts down
        """
        return self._hosts_down
    
    @property
    def num_hosts(self) -> Union[None,int]:
        """ Total number of hosts
        """
        return self._num_hosts

    @property
    def scan_info(self) -> Union[None,str]:
        """ Scan information
        """
        return self._scan_info

    @scan_info.setter
    def scan_info(self, v):
        assert v is None or isinstance(v, dict), 'NmapScanResult.scan_info must be None or a dictionary'

        if v is None:
            self._scan_info = {}
        else:
            self._scan_info = v

    @property
    def verbose(self) -> Union[None,int]:
        """ Verbosity level
        """
        return self._verbose

    @verbose.setter
    def verbose(self, v):
        assert v is None or isinstance(v, (int, str)), 'NmapScanResult.verbose must be None, int or str'
        
        if v is not None:
            self._verbose = int(v)
        else:
            self._verbose = None

    @property
    def debug(self) -> Union[None,int]:
        """ Debugging level
        """
        return self._debug

    @debug.setter
    def debug(self, v):
        assert v is None or isinstance(v, (int, str)), 'NmapScanResult.debug must be None, int or str'
        
        if v is not None:
            self._debug = int(v)
        else:
            self._debug = None

    @property
    def tolerant_errors(self) -> Union[None,str]:
        """ String containing tolerant errors
        """
        return self._tolerant_errors
    
    @tolerant_errors.setter
    def tolerant_errors(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.tolerant_errors must be None or str'

        self._tolerant_errors = v

    def __len__(self):
        return len(self._hosts)
    
    def __getitem__(self, v):
        """ Flexible get item by position, ip, ip ranges, hostnames and any combination of the last three.

        If an integer is specified, then it will return a host in position v, acting as a normal list.
        If an str is specified, then it will check if the provided string has spaces (which indicates that the user is requesting multiple hosts)
        and if so, it will do a single search for all of them.
        If tuple is set, then the user has specified multiple arguments separated by commas, so it will act the same as handling strings with spaces.

        If the user specifies a multi-host value, then the resposne will be a list, empty or not.
        If the user specifies an integer, or a single host to be return, then the method will return None or the host, if it exists.

        :param v: Value, or values, to retrive from the hosts list.
        """

        if isinstance(v, int):
            return self._hosts[v]
        elif isinstance(v, (str, tuple)):
            to_return = []
            multi_return = False
            if isinstance(v, str):
                v = v.strip()
                if ' ' in v:
                    v = [x for x in v.split() if v]
                else:
                    v = [v]

            if len(v) > 1:
                multi_return = True

            for i in v:
                ips = []
                hostnames = []
                if utils._SINGLE_IP_ADDRESS_REGEX.fullmatch(i):
                    ips.append(i)
                elif utils._IP_ADDRESS_WITH_CIDR_REGEX.fullmatch(i):
                    ips.extend(utils.dispatch_network(i))
                elif utils._IP_RANGE_REGEX.fullmatch(i):
                    split_value = i.split('-')
                    ips.extend(utils.ip_range(split_value[0], split_value[1]))
                elif utils._PARTIAL_IP_RANGE_REGEX.fullmatch(i):
                    ips.extend(utils.partial_ip_range(i))
                else:
                    hostnames.append(i)
            
            
            for host in self._hosts:
                if host.ipv4 in ips or [i for i in host.hostnames() if i in hostnames]:
                    to_return.append(host)
            
            if not multi_return:
                try:
                    return to_return[0]
                except IndexError:
                    return None
            
            else:
                return to_return

        else:
            raise TypeError('Invalid index type. Must be int, str or tuple but found {}'.format(type(v)))

    def __next__(self):
        """ Defines the iterator behaviour
        """
        if (self._index + 1) < len(self._hosts):
            self._index += 1
            return self._hosts[self._index]
        else:
            raise StopIteration

    def __iter__(self):
        """ Return an iterator for the hosts
        """

        return iter(self._hosts)

    def __len__(self):
        """ Get the length of the result object
        """

        return len(self._hosts)

    def __contains__(self, v):
        """ Check if an element v is in result
        """
        is_ip = False
        if utils._SINGLE_IP_ADDRESS_REGEX.fullmatch(v):
            is_ip = True

        for i in self:
            if (is_ip and i.ipv4 == v) or (not is_ip and v in i.hostnames()):
                return True

        return False

    def _add_hosts(self, *args):
        """ Add hosts objects to the current instance.

        :param args: Any number of Hosts instances to add
        :raises TypeError: If any of the instances is not from the Host class
        """

        for i in args:
            if not isinstance(i, Host):
                raise TypeError('Cannot add non-Host objects to a NmapScanResult')
            self._hosts.append(i)

    def scanned_hosts(self):
        """ Returns the hosts objects from the hosts that responded to the scan
        
        :return: List of hosts objects
        """

        return self._hosts
    
    def get_output(self, output_type):
        """ Returns, if any, the specified output format from 'xml', 'grep' or 'normal'.

        :returns: String representing the Nmap output from the specified output_type, or None if there is no one
        :raises ValueError: If the output_type has an invalid value.
        """

        if output_type not in OUTPUT_FORMATS:
            raise ValueError('Invalid output_type value. Expected on of the follwong: {}'.format(', '.join(OUTPUT_FORMATS)))
        
        if output_type == 'xml':
            return self._xml_output
        elif output_type == 'normal':
            return self._normal_output
        elif output_type == 'grep':
            return self._grep_output