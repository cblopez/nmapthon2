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

# Offers an object-oriented representation of the scan status

import re

from .exceptions import XMLParsingError

import datetime
import xml.etree.ElementTree as ET


TASK_PROGRESS_REGEX = re.compile(r'<taskprogress .+\/>')
XML_TASK_EXTRACTOR_REGEX = re.compile(r'[a-z]+="[^"]+"')


class Status:
    """ Represents the Nmap scan status.
    
    The status has information from the task being performed, the timestamp, the completion percentage, the remaining
    number of hosts and the ETA.
    """

    __slots__ = ('_task', '_time', '_percent', '_remaining', '_etc')

    def __init__(self, **kwargs):
        self.task = kwargs.get('task', None)
        self.time = kwargs.get('time', None)
        self.percent = kwargs.get('percent', None)
        self.remaining = kwargs.get('remaining', None)
        self.etc = kwargs.get('etc', None)

    @classmethod
    def from_raw_xml(cls, xml):
        """ Creates a new instance from raw XML output

        :param xml: Raw utf8 decoded XML output
        :returns: New Status instance
        :raises XMLParsingError: If the output cannot be parsed to XML
        """
        try:
            last_status = TASK_PROGRESS_REGEX.findall(xml)[-1]
        except IndexError:
            return None
        else:
            status_info = {}
            for key_value_pair in XML_TASK_EXTRACTOR_REGEX.findall(last_status):
                split_values = key_value_pair.split('=')
                key = split_values[0]
                value = ''.join(split_values[1:]).strip('"')
                status_info[key] = value

            return cls(**status_info)

    @property
    def task(self):
        return self._task
    
    @task.setter
    def task(self, v):
        assert v is None or isinstance(v, str), 'Status.task can only be None or str'
        
        self._task = v

    @property
    def time(self):
        return self._time
    
    @time.setter
    def time(self, v):
        assert v is None or isinstance(v, (str, int)), 'Status.time can only be None, str or int'
        
        self._time = datetime.datetime.fromtimestamp(int(v))
    
    @property
    def percent(self):
        return self._percent
    
    @percent.setter
    def percent(self, v):
        assert v is None or isinstance(v, (str,float)), 'Status.percent can only be None, str or float'
        
        self._percent = float(v)
    
    @property
    def remaining(self):
        return self._remaining
    
    @remaining.setter
    def remaining(self, v):
        assert v is None or isinstance(v, (str, int)), 'Status.remaining can only be None, str or int'
        
        if v:
            self._remaining = int(v)
        else:
            self._remaining = None
    
    @property
    def etc(self):
        return self._etc
    
    @etc.setter
    def etc(self, v):
        assert v is None or isinstance(v, (str,int)), 'Status.etc can only be None, str or int'
        
        if v:
            self._etc = datetime.datetime.fromtimestamp(int(v))
        else:
            self._etc = None
