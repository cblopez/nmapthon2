Retrieving results
==================

.. toctree::
    :titlesonly:
    :maxdepth: 1

    result_info
    result_host
    result_port
    result_service
    result_os
    result_traceroute
    result_scripts
    result_output

Successfully completing scans, resuming scans or importing XML files will return an ``NmapScanResult`` object. This object contains all the information from the 
performed scan. Scan information includes:

* Overall scan information.
* Scanned hosts, ports and services
* Nmap's NSE scripts results
* NSE script results from an ``NSE`` object from the Nmapthon2 library.

On the following sub-section, you will learn how to get this information through several properties, methods and control flows.