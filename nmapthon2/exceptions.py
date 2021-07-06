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

__all__ = ['NmapScanError', 'InvalidPortError', 'InvalidArgumentError', 'MalformedIpAddressError',
           'EngineError', '_XMLParsingError']


class NmapScanError(Exception):
    """ Exception class for nmap scanning errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class InvalidPortError(NmapScanError):
    """ Exception class for port assignment and parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class MalformedIpAddressError(NmapScanError):
    """ Exception class for target assignment and parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class InvalidArgumentError(NmapScanError):
    """ Exception class for nmap arguments assignment and parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class _XMLParsingError(Exception):
    """ Exception class for nmap output parsing errors.
    """

    def __init__(self, message):
        Exception.__init__(self, message)


class EngineError(Exception):
    """ Exception class for PyNSEEngine errors
    """

    def __init__(self, msg):
        super().__init__(msg)