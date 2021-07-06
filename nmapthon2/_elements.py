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


class Host:
    """ Holds the information from an individual target that responded to the scan.

    Such information is generic host information like the status, reason, reason TTL...
    Ports information, including the services objects, CPEs, and so on... and even hosts
    and services scripts. A Host instance may save other elements instances to hold information.
    """

    __slots__ = ('_state', '_reason', '_reason_ttl')

    def __init__(self, **kwargs):
        self.state = kwargs.get('state', None)
        self.reason = kwargs.get('reason', None)
        self.reason_ttl = kwargs.get('reason_ttl', None)

    @property
    def state(self):
        return self._state
    
    @state.setter
    def state(self, v):
        assert v is None or isinstance(v, str), 'Host.state must be None or str'

        self._state = v

    @property
    def reason(self):
        return self._reason

    @reason.setter
    def reason(self, v):
        assert v is None or isinstance(v, str), 'Host.reason must be None or str'

        self,_reason = v
    
