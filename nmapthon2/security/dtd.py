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


# This file contains the raw Document Type Definition for Nmap XML

import io

from lxml import etree


NMAP_XML_DTD = etree.DTD(io.StringIO( '''<!--
    nmap.dtd
    This is the DTD for Nmap's XML output (-oX) format.
    $Id$

    Originally written by:
    William McVey <wam@cisco.com> <wam+nmap@wamber.net>

    Now maintained by Fyodor <fyodor@nmap.org> as part of Nmap.     

    To validate using this file, simply add a DOCTYPE line similar to:
    <!DOCTYPE nmaprun SYSTEM "nmap.dtd">
    to the nmap output immediately below the prologue (the first line).  This
    should allow you to run a validating parser against the output (so long
    as the DTD is in your parser's DTD search path).

    Bugs:
    Most of the elements are "locked" into the specific order that nmap
    generates, when there really is no need for a specific ordering.
    This is primarily because I don't know the xml DTD construct to
    specify "one each of this list of elements, in any order".  If there
    is a construct similar to SGML's '&' operator, please let me know.

    Portions Copyright (c) 2001-2022 Nmap Software LLC
    Portions Copyright (c) 2001 by Cisco systems, Inc.
 
    Permission to use, copy, modify, and distribute modified and
    unmodified copies of this software for any purpose and without fee is
    hereby granted, provided that (a) this copyright and permission notice
    appear on all copies of the software and supporting documentation, (b)
    the name of Cisco Systems, Inc. not be used in advertising or
    publicity pertaining to distribution of the program without specific
    prior permission, and (c) notice be given in supporting documentation
    that use, modification, copying and distribution is by permission of
    Cisco Systems, Inc.
 
    Cisco Systems, Inc. makes no representations about the suitability
    of this software for any purpose.  THIS SOFTWARE IS PROVIDED ``AS
    IS'' AND WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING,
    WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
    FITNESS FOR A PARTICULAR PURPOSE.
-->

<!-- parameter entities to specify common "types" used elsewhere in the DTD -->
<!ENTITY % attr_alpha "CDATA" >
<!ENTITY % attr_numeric "CDATA" >
<!ENTITY % attr_ipaddr "CDATA" >
<!ENTITY % attr_percent "CDATA" >
<!ENTITY % attr_type "(ipv4 | ipv6 | mac)" >
<!ENTITY % attr_bool "(true | false)" >

<!ENTITY % host_states "(up|down|unknown|skipped)" >

<!-- see: nmap.c:statenum2str for list of port states -->
<!-- Maybe they should be enumerated as in scan_types below , but I -->
<!-- don't know how to escape states like open|filtered -->
<!ENTITY % port_states "CDATA" >

<!ENTITY % hostname_types "(user|PTR)" >

<!-- see output.c:output_xml_scaninfo_records for scan types -->
<!ENTITY % scan_types "(syn|ack|bounce|connect|null|xmas|window|maimon|fin|udp|sctpinit|sctpcookieecho|ipproto)" >

<!-- <!ENTITY % ip_versions "(ipv4)" > -->

<!ENTITY % port_protocols "(ip|tcp|udp|sctp)" >

<!-- Service detection confidence level (portlist.h:struct serviceDeductions)
--> 
<!ENTITY % service_confs  "( 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10)" >

<!-- This element was started in nmap.c:nmap_main().
     It represents to the topmost element of the output document.
-->
<!ELEMENT nmaprun      (scaninfo*, verbose, debugging,
                        ( target | taskbegin | taskprogress | taskend | hosthint |
                            prescript | postscript | host | output)*,
                            runstats) >
<!ATTLIST nmaprun
			scanner		(nmap)		#REQUIRED
			args		CDATA		#IMPLIED
			start		%attr_numeric;	#IMPLIED
			startstr	CDATA	        #IMPLIED
			version		CDATA		#REQUIRED
			profile_name	CDATA		#IMPLIED
			xmloutputversion CDATA		#REQUIRED
>

<!-- this element is written in output.c:doscaninfo() -->
<!ELEMENT scaninfo	EMPTY >
<!ATTLIST scaninfo
			type		%scan_types;	 #REQUIRED
			scanflags	CDATA		 #IMPLIED
			protocol	%port_protocols; #REQUIRED
			numservices	%attr_numeric;	 #REQUIRED
			services	CDATA		 #REQUIRED
>

<!-- these elements are written in nmap.c:nmap_main() -->
<!ELEMENT verbose	EMPTY >
<!ATTLIST verbose	level		%attr_numeric;	#IMPLIED >


<!ELEMENT debugging 	EMPTY >
<!ATTLIST debugging	level		%attr_numeric;	#IMPLIED >

<!ELEMENT target	EMPTY >
<!ATTLIST target	specification	CDATA		#REQUIRED
			status		(skipped)	#IMPLIED
			reason		(invalid)	#IMPLIED
>

<!-- this element is written in timing.c:beginOrEndTask() -->
<!ELEMENT taskbegin	EMPTY >
<!ATTLIST taskbegin
			task		CDATA		#REQUIRED
			time		%attr_numeric;	#REQUIRED
			extrainfo	CDATA		#IMPLIED
>

<!-- this element is written in timing.c:printStats() -->
<!ELEMENT taskprogress	EMPTY >
<!ATTLIST taskprogress
			task		CDATA		#REQUIRED
			time		%attr_numeric;	#REQUIRED
			percent		%attr_percent;	#REQUIRED
			remaining	%attr_numeric;	#REQUIRED
			etc		%attr_numeric;	#REQUIRED
>

<!-- this element is written in timing.c:beginOrEndTask() -->
<!ELEMENT taskend	EMPTY >
<!ATTLIST taskend
			task		CDATA		#REQUIRED
			time		%attr_numeric;	#REQUIRED
			extrainfo	CDATA		#IMPLIED
>

<!-- 
     this element is started in nmap.c:nmap_main() and filled by
     output.c:write_host_status(), output.c:printportoutput(), and
     output.c:printosscanoutput()
-->
<!ELEMENT host		( status, address , (address | hostnames |
                          smurf | ports | os | distance | uptime | 
                          tcpsequence | ipidsequence | tcptssequence |
                          hostscript | trace)*, times? ) >
<!ATTLIST host
			starttime	%attr_numeric;	#IMPLIED
			endtime		%attr_numeric;	#IMPLIED
			timedout	%attr_bool;	#IMPLIED
			comment		CDATA		#IMPLIED
>

<!-- these elements are written by scan_engine.c:ultrascan_host_pspec_update() -->
<!ELEMENT hosthint (status,address+,hostnames?) >

<!-- these elements are written by output.c:write_xml_initial_hostinfo() -->
<!ELEMENT status	EMPTY >
<!ATTLIST status	state		%host_states;	#REQUIRED 
		  reason	    CDATA	#REQUIRED 
		  reason_ttl	CDATA	#REQUIRED			
 >

<!ELEMENT address	EMPTY >
<!ATTLIST address	
			addr		%attr_ipaddr;	#REQUIRED
			addrtype	%attr_type;	"ipv4"
			vendor		CDATA		#IMPLIED
>

<!ELEMENT hostnames	(hostname)* >
<!ELEMENT hostname	EMPTY >
<!ATTLIST hostname
			name		CDATA		#IMPLIED
			type		%hostname_types; #IMPLIED
>


<!-- this element is written by output.c:write_host_status() -->
<!ELEMENT smurf		EMPTY >
<!ATTLIST smurf		responses	%attr_numeric;	#REQUIRED >

<!-- these elements are written by output.c:printportoutput() -->

<!ELEMENT ports		(extraports* , port*) >

<!ELEMENT extraports	(extrareasons)* >
<!ATTLIST extraports
			state		%port_states;	#REQUIRED
			count		%attr_numeric;  #REQUIRED	
>

<!ELEMENT extrareasons EMPTY >
<!ATTLIST extrareasons
			reason		CDATA	#REQUIRED
			count		CDATA	#REQUIRED
			proto	%port_protocols; #IMPLIED
			ports		CDATA	#IMPLIED
>

<!ELEMENT port		(state , owner? , service?, script*) >
<!ATTLIST port
			protocol	%port_protocols;	#REQUIRED
			portid		%attr_numeric;	#REQUIRED
>

<!ELEMENT state		EMPTY >
<!ATTLIST state
		state		%port_states;	#REQUIRED 
		reason		CDATA	#REQUIRED
		reason_ttl	CDATA	#REQUIRED			
		reason_ip	CDATA	#IMPLIED
>

<!ELEMENT owner		EMPTY >
<!ATTLIST owner		name		CDATA		#REQUIRED >

<!ELEMENT service	(cpe*) >
<!ATTLIST service
			name		CDATA		#REQUIRED
			conf		%service_confs;	#REQUIRED
                        method          (table|probed)  #REQUIRED
                        version         CDATA           #IMPLIED
                        product         CDATA           #IMPLIED
                        extrainfo       CDATA           #IMPLIED
			tunnel		(ssl)		#IMPLIED
			proto		(rpc)		#IMPLIED
			rpcnum		%attr_numeric;	#IMPLIED
			lowver		%attr_numeric;	#IMPLIED
			highver		%attr_numeric;	#IMPLIED
                        hostname        CDATA           #IMPLIED
                        ostype          CDATA           #IMPLIED
                        devicetype      CDATA           #IMPLIED
                        servicefp       CDATA           #IMPLIED
>

<!ELEMENT cpe (#PCDATA)>

<!ELEMENT script	(#PCDATA|table|elem)* >
<!ATTLIST script	
	id	CDATA	#REQUIRED
	output	CDATA	#REQUIRED
>

<!ELEMENT table	(table|elem)* >
<!ATTLIST table
    key CDATA #IMPLIED
>

<!ELEMENT elem	(#PCDATA)>
<!ATTLIST elem
    key CDATA #IMPLIED
>

<!ELEMENT os		( portused* , osmatch*, osfingerprint* ) >

<!ELEMENT portused	EMPTY >
<!ATTLIST portused
			state 		%port_states;	#REQUIRED
			proto 		%port_protocols; #REQUIRED
			portid 		%attr_numeric;	#REQUIRED
>
<!ELEMENT osclass      (cpe*) >
<!ATTLIST osclass
                       vendor          CDATA           #REQUIRED
                       osgen           CDATA           #IMPLIED
                       type            CDATA           #IMPLIED
                       accuracy        CDATA           #REQUIRED
                       osfamily        CDATA           #REQUIRED
>


<!ELEMENT osmatch	(osclass*) >
<!ATTLIST osmatch
			name		CDATA		#REQUIRED
			accuracy	%attr_numeric;	#REQUIRED
			line    	%attr_numeric;	#REQUIRED
>

<!ELEMENT osfingerprint	EMPTY >
<!ATTLIST osfingerprint
			fingerprint	CDATA		#REQUIRED
>

<!ELEMENT distance	EMPTY >
<!ATTLIST distance
			value		%attr_numeric;	#REQUIRED
>

<!ELEMENT uptime	EMPTY >
<!ATTLIST uptime
			seconds		%attr_numeric;	#REQUIRED
			lastboot	CDATA		#IMPLIED
>

<!ELEMENT tcpsequence	EMPTY >
<!ATTLIST tcpsequence
			index		%attr_numeric;	#REQUIRED
			difficulty	CDATA		#REQUIRED
			values		CDATA		#REQUIRED
>

<!ELEMENT ipidsequence	EMPTY >
<!ATTLIST ipidsequence
			class		CDATA		#REQUIRED
			values		CDATA		#REQUIRED
>

<!ELEMENT tcptssequence	EMPTY >
<!ATTLIST tcptssequence
			class		CDATA		#REQUIRED
			values		CDATA		#IMPLIED
>

<!ELEMENT trace (hop*) >
<!ATTLIST trace
      proto   CDATA   #IMPLIED
      port    CDATA   #IMPLIED
>

<!ELEMENT hop EMPTY>
<!ATTLIST hop
      ttl     CDATA   #REQUIRED
      rtt     CDATA   #IMPLIED
      ipaddr  CDATA   #IMPLIED
      host    CDATA   #IMPLIED
>

<!ELEMENT times EMPTY>
<!ATTLIST times
	srtt	CDATA	#REQUIRED
	rttvar	CDATA	#REQUIRED
	to	CDATA	#REQUIRED
>

<!-- For embedding another type of output (screen output) like Zenmap does. -->
<!ELEMENT output (#PCDATA)>
<!ATTLIST output type  (interactive)  #IMPLIED>

<!-- these elements are generated in output.c:printfinaloutput() -->
<!ELEMENT runstats	(finished, hosts)>

<!ELEMENT finished	EMPTY >
<!ATTLIST finished	time		%attr_numeric;	#REQUIRED 
                        timestr		CDATA	        #IMPLIED
			elapsed		%attr_numeric;	#REQUIRED
                        summary		CDATA	        #IMPLIED
                        exit		(error|success) #IMPLIED
                        errormsg	CDATA	        #IMPLIED
>

<!ELEMENT hosts		EMPTY >
<!ATTLIST hosts
			up		%attr_numeric;	"0"
			down		%attr_numeric;	"0"
			total		%attr_numeric;	#REQUIRED
>

<!ELEMENT hostscript ( script+ )>
<!ELEMENT prescript ( script+ )>
<!ELEMENT postscript ( script+ )>'''))