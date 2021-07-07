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

from ._elements import Host


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

    Additionally, these hosts could also have Operating System results and PyNSEEngine
    results, which are unique from this library.
    """

    __slots__ = ('_scanner', '_arguments', '_start_timestamp', '_start_datetime',
                 '_version', '_end_timestamp', '_end_datetime', '_elapsed', '_summary',
                 '_exit_status', '_hosts_up', '_hosts_down', '_num_hosts', '_scan_info',
                 '_verbose', '_debug', '_hosts')

    def __init__(self, **kwargs):
        self.scanner = kwargs.get('scanner', None)
        self.arguments = kwargs.get('arguments', None)
        self.start_timestamp = kwargs.get('start', None)
        self.start_datetime = kwargs.get('start', None)
        self.version = kwargs.get('version', None)
        self.end_timestamp = kwargs.get('end', None)
        self.end_datetime = kwargs.get('end', None)
        self.elapsed = kwargs.get('elapsed', None)
        self.summary = kwargs.get('summary', None)
        self.exit_status = kwargs.get('exit_status', None)

        self._hosts_up = kwargs.get('hosts_up', None)
        self._hosts_down = kwargs.get('hosts_down', None)
        self._num_hosts = kwargs.get('num_hosts', None)
    
        self.scan_info = kwargs.get('scan_info', None)
        self.verbose = kwargs.get('verbose', None)
        self.debug = kwargs.get('debug', None)

        self._hosts = []

    @property
    def scanner(self):
        return self._scanner
    
    @scanner.setter
    def scanner(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.scanner must be None or str'

        self._scanner = v
    
    @property
    def arguments(self):
        return self._arguments
    
    @arguments.setter
    def arguments(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.arguments must be None or str'

        self._arguments = v

    @property
    def start_timestamp(self):
        return self._start_timestamp
    
    @start_timestamp.setter
    def start_timestamp(self, v):
        assert v is None or isinstance(v, str) or isinstance(v, int), 'NmapScanResult.start_timestamp must be None, str or int'

        if v is not None:
            self._start_timestamp = int(v)
        else:
            self._start_timestamp = v
                
    
    @property
    def start_datetime(self):
        return self._start_datetime
    
    @start_datetime.setter
    def start_datetime(self, v):
        
        if v is not None:
            self._start_datetime = datetime.datetime.fromtimestamp(v)
        else:
            self._start_datetime = None

    @property
    def version(self):
        return self._version
    
    @version.setter
    def version(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.start_timestamp must be None or str'

        self._version = v

    @property
    def end_timestamp(self):
        return self._end_timestamp
    
    @end_timestamp.setter
    def end_timestamp(self, v):
        assert v is None or isinstance(v, str) or isinstance(v, int), 'NmapScanResult.end_timestamp must be None, str or int'

        if v is not None:
            self._end_timestamp = int(v)
        else:
            self._end_timestamp = v
    
    @property
    def end_datetime(self):
        return self._end_datetime
    
    @end_datetime.setter
    def end_datetime(self, v):
        
        if v is not None:
            self._end_datetime = datetime.datetime.fromtimestamp(v)
        else:
            self._end_datetime = None

    @property
    def elapsed(self):
        return self._elapsed
    
    @elapsed.setter
    def elapsed(self, v):
        assert v is None or isinstance(v, str) or isinstance(v, float), 'NmapScanResult.elapsed must be None, str or float'
        try:
            self._elapsed = float(v)
        except ValueError:
            pass
    
    @property
    def summary(self):
        return self._summary
    
    @summary.setter
    def summary(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.summary must be None or str'
        
        self._summary = v
    
    @property
    def exit_status(self):
        return self._exit_status
    
    @exit_status.setter
    def exit_status(self, v):
        assert v is None or isinstance(v, str), 'NmapScanResult.exit_status must be None or str'
        
        self._exit_status = v

    @property
    def hosts_up(self):
        return self._hosts_up
    
    @property
    def hosts_down(self):
        return self._hosts_down
    
    @property
    def num_hosts(self):
        return self._num_hosts

    @property
    def scan_info(self):
        return self._scan_info

    @scan_info.setter
    def scan_info(self, v):
        assert v is None or isinstance(v, dict), 'NmapScanResult.scan_info must be None or a dictionary'

        if v is None:
            self._scan_info = {}
        else:
            self._scan_info = v

    @property
    def verbose(self):
        return self._verbose

    @verbose.setter
    def verbose(self, v):
        assert v is None or isinstance(v, (int, str)), 'NmapScanResult.verbose must be None, int or str'
        
        if v is not None:
            self._verbose = int(v)
        else:
            self._verbose = None

    @property
    def debug(self):
        return self._debug

    @debug.setter
    def debug(self, v):
        assert v is None or isinstance(v, (int, str)), 'NmapScanResult.debug must be None, int or str'
        
        if v is not None:
            self._debug = int(v)
        else:
            self._debug = None

    def _add_hosts(self, *args):
        """ Add hosts objects to the current instance.

        :param args: Any number of Hosts instances to add
        :raises TypeError: If any of the instances is not from the Host class
        """

        for i in args:
            if not isinstance(i, Host):
                raise TypeError('Cannot add non-Host objects to a NmapScanResult')
            self._hosts.append(i)

    