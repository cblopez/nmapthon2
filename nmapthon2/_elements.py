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

import datetime


class Host:
    """ Holds the information from an individual target that responded to the scan.

    Such information is generic host information like the status, reason, reason TTL...
    Ports information, including the services objects, CPEs, and so on... and even hosts
    and services scripts. A Host instance may save other elements instances to hold information.
    """

    __slots__ = ('_state', '_reason', '_reason_ttl', '_start_time', '_end_time', '_ipv4', '_ipv6',
                 '_hostnames', '_ports', '_oses', '_fingerprint', '_trace')

    def __init__(self, **kwargs):
        self.state = kwargs.get('state', None)
        self.reason = kwargs.get('reason', None)
        self.reason_ttl = kwargs.get('reason_ttl', None)
        self.start_time = kwargs.get('start_time', None)
        self.end_time = kwargs.get('end_time', None)
        self.ipv4 = kwargs.get('ipv4', None)
        self.ipv6 = kwargs.get('ipv6', None)
        self.fingerprint = kwargs.get('fingerprint', None)
        self._hostnames = kwargs.get('hostnames', {})
        self._ports = kwargs.get('ports', [])
        self._oses = kwargs.get('oses', [])
        self._trace = kwargs.get('trace', [])

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

        self._reason = v

    @property
    def reason_ttl(self):
        return self._reason_ttl

    @reason_ttl.setter
    def reason_ttl(self, v):
        assert v is None or isinstance(v, str), 'Host.reason_ttl must be None or str'

        self._reason_ttl = int(v)

    @property
    def start_time(self):
        return self._start_time

    @start_time.setter
    def start_time(self, v):

        if v is not None:
            self._start_time = datetime.datetime.fromtimestamp(int(v))
        else:
            self._start_time = None

    @property
    def end_time(self):
        return self._start_time

    @end_time.setter
    def end_time(self, v):

        if v is not None:
            self._end_time = datetime.datetime.fromtimestamp(int(v))
        else:
            self._end_time = None

    @property
    def ip(self):
        if self._ipv4 is not None:
            return self._ipv4
        else:
            return self._ipv6
    
    @property
    def ipv4(self):
        return self._ipv4

    @ipv4.setter
    def ipv4(self, v):
        assert v is None or isinstance(v, str)

        self._ipv4 = v
    
    @property
    def ipv6(self):
        return self._ipv6

    @ipv6.setter
    def ipv6(self, v):
        assert v is None or isinstance(v, str)

        self._ipv6 = v

    @property
    def fingerprint(self):
        return self._fingerprint
    
    @fingerprint.setter
    def fingerprint(self, v):
        assert v is None or isinstance(v, str)

        self._fingerprint = v

    def _add_port(self, *args):
        """ Add a port object binded to the current instance

        :param args: Any number of Port instances
        """

        for i in args:
            if not isinstance(i, Port):
                raise TypeError('Cannot add non-Port instance to the host')
            
            self._ports.append(i)

    def _add_os(self, os):
        """ Bind an OperatingSystem object to the current instance

        :param os: OperatingSystem instance to buy.
        :raises TypeError: If os is not an OperatingSystem
        """

        if not isinstance(os, OperatingSystem):
            raise TypeError('Cannot bind non-OperatingSystem instance to host')
            
        self._oses.append(os)

    def _add_hop(self, hop_instance):
        """ Add a Hop instance to the current host trace information

        :param hop_instance: Instance to be added
        :raises TypeError if the paramer is not a Hop object
        """

        if not isinstance(hop_instance, Hop):
            raise TypeError('Cannot bind a non-Hop object to a host`s trace')
        
        self._trace.append(hop_instance)

    def hostnames(include_type: bool = False) -> list:
        """ Return all the host related hostnames.
        
        if include_type is set to True, the method will return a list of tuples where
        the first element is the hostname, and the second is the type of hostname related to the
        first element.

        :param include_type: Set to True to include the hostnames types on the result.
        :returns: List of hostnames or list of tuples with (hostname, hostname_type).
        """

        if not include_type:
            return [x for x in self._hostnames.keys()]
        else:
            return [(x, y) for x, y in self._hostnames.items()]


class Port:
    """ A port element represents a unique port from an individual protocol related to a host.

    A port element has information from the port number, the protocol, the port state and, if any,
    the service running on that port. Note that the service is not a primitive, but an instance of the
    Service class.
    """

    __slots__ = ('_protocol', '_number', '_state', '_reason', '_reason_ttl', '_service')

    def __init__(self, **kwargs):
        self.protocol = kwargs.get('protocol', None)
        self.number = kwargs.get('number', None)
        self.state = kwargs.get('state', None)
        self.reason = kwargs.get('reason', None)
        self.reason_ttl = kwargs.get('reason_ttl', None)

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, v):
        assert v is None or isinstance(v, str)

    @property
    def number(self):
        return self._number
    
    @number.setter
    def number(self, v):
        assert v is None or isinstance(v, (str, int))

        self._number = int(v)

    @property
    def state(self):
        return self._state

    @state.setter
    def state(self, v):
        assert v is None or isinstance(v, str)

        self._state = v

    @property
    def reason(self):
        return self._reason

    @reason.setter
    def reason(self, v):
        assert v is None or isinstance(v, str)

        self._reason = v

    @property
    def reason_ttl(self):
        return self._reason_ttl

    @reason_ttl.setter
    def reason_ttl(self, v):
        assert v is None or isinstance(v, (str, int))

        self._reason_ttl = int(v)

    @property
    def service(self):
        return self._service

    def _add_service(self, service):
        """ Bind a service with the current instance
        
        :param service: Service instance to bind
        """

        if not isinstance(service, Service):
            raise TypeError('Cannot bind a non-Service instance to a port')

        self._service = service  


class Service:
    """ Represents a service binded to a port.

    A service can be associated with a name, product, version and extrainfo. It addtionally
    has information about the tunneling protocol, service CPE(s) and scripts.
    """

    __slots__ = ('_name', '_product', '_version', '_extrainfo', '_tunnel', '_method',
                 '_conf', '_cpes', '_scripts', '_port')

    def __init__(self, **kwargs):
        self.name = kwargs.get('name', None)
        self.product = kwargs.get('product', None)
        self.version = kwargs.get('version', None)
        self.extrainfo = kwargs.get('extrainfo', None)
        self.tunnel = kwargs.get('tunnel', None)
        self.method = kwargs.get('method', None)
        self.conf = kwargs.get('conf', None)
        self.cpes = kwargs.get('cpes', [])
        self.port = kwargs.get('port', None)
        
        self._scripts = {}

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, v):
        assert v is None or isinstance(v, str)

        self._name = v

    @property
    def product(self):
        return self._product

    @product.setter
    def product(self, v):
        assert v is None or isinstance(v, str)

        self._product = v

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, v):
        assert v is None or isinstance(v, str)

        self._version = v
    
    @property
    def extrainfo(self):
        return self._extrainfo

    @extrainfo.setter
    def extrainfo(self, v):
        assert v is None or isinstance(v, str)

        self._extrainfo = v

    @property
    def tunnel(self):
        return self._tunnel

    @tunnel.setter
    def tunnel(self, v):
        assert v is None or isinstance(v, str)

        self._tunnel = v
    
    @property
    def method(self):
        return self._method

    @method.setter
    def method(self, v):
        assert v is None or isinstance(v, str)

        self._method = v
    
    @property
    def conf(self):
        return self._conf

    @conf.setter
    def conf(self, v):
        assert v is None or isinstance(v, str)

        self._conf = float(v)

    @property
    def cpes(self):
        return self._cpes

    @cpes.setter
    def cpes(self, v):
        assert v is None or isinstance(v, list)

        self._cpes = v

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, v):
        assert v is None or isinstance(v, (str, int))

        self._port = int(v)

    def _add_script(self, script_name, script_output):
        """ Add a script name + output to tthe service instance.

        :param script_name: Script identifier
        :param script_output: Script output
        """

        if script_name in self._scripts:
            raise RuntimeError('Script with identifier "{}" already exists, please name it differently'.format(script_name))

        self._scripts[script_name] = script_output


class OperatingSystem:
    """ Represents a host's operating system

    An operating system contains information from an OS match, which includes the OS name, the
    accuracy and line. It also saves information from the family and generation, in case they exist,
    plus any CPE matched with it.
    """

    __slots__ = ('_name', '_accuracy', '_type', '_vendor', '_family', '_generation', '_cpe')

    def __init__(self, **kwargs):
        self.name = kwargs.get('name', None)
        self.accuracy = kwargs.get('accuracy', None)
        self.os_type = kwargs.get('type', None)
        self.vendor = kwargs.get('vendor', None)
        self.family = kwargs.get('family', None)
        self.generation = kwargs.get('generation', None)
        self.cpe = kwargs.get('cpe', None)

    @property
    def name(self, v):
        return self._name

    @name.setter
    def name(self, v):
        assert v is None or isinstance(v, str)

        self._name = v

    @property
    def accuracy(self, v):
        return self._accuracy

    @accuracy.setter
    def accuracy(self, v):
        assert v is None or isinstance(v, str)

        self._accuracy = float(v)
    
    @property
    def os_type(self, v):
        return self._type

    @os_type.setter
    def os_type(self, v):
        assert v is None or isinstance(v, str)

        self._type = v
    
    @property
    def vendor(self, v):
        return self._vendor

    @vendor.setter
    def vendor(self, v):
        assert v is None or isinstance(v, str)

        self._vendor = v
    
    @property
    def family(self, v):
        return self._family

    @family.setter
    def family(self, v):
        assert v is None or isinstance(v, str)

        self._family = v

    @property
    def generation(self, v):
        return self._generation

    @generation.setter
    def generation(self, v):
        assert v is None or isinstance(v, str)

        self._generation = v

    @property
    def cpe(self, v):
        return self._cpe

    @cpe.setter
    def cpe(self, v):
        assert v is None or isinstance(v, str)

        self._cpe = v


class Hop:
    """ A Hop is a representantion of an ICMP hop performed by traceroute.

    It saves information from the hostname, IP, Rount-Trip-Time and Time-To-Live
    """

    __slots__ = ('_host', '_ip', '_rtt', '_ttl')

    def __init__(self, **kwargs):
        self.host = kwargs.get('host', None)
        self.ip = kwargs.get('ip', None)
        self.rtt = kwargs.get('rtt', None)
        self.ttl = kwargs.get('ttl', None)

    @property
    def host(self):
        return self._host
    
    @host.setter
    def host(self, v):
        assert v is None and isinstance(v, str)

        self._host = v
    
    @property
    def ip(self):
        return self._ip
    
    @ip.setter
    def ip(self, v):
        assert v is None and isinstance(v, str)

        self._ip = v
    
    @property
    def rtt(self):
        return self._rtt
    
    @rtt.setter
    def rtt(self, v):
        assert v is None and isinstance(v, str)

        self._rtt = v
    
    @property
    def ttl(self):
        return self._ttl
    
    @ttl.setter
    def ttl(self, v):
        assert v is None and isinstance(v, str)

        self._ttl = v
