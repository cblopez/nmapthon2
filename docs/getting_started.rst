Getting Started
===============

Nmapthon2 is a Python module that allows you to highly interact with the Nmap tool and even extend its capabilities with custom Python functions to 
execute security checks and parse built-in NSE scripts output. With this module you will be able to:

* Execute Nmap scans and easily retrieve all the results with human-readable code.
* Execute Nmap scans asynchronously.
* Use new Nmap functionalities that have been designed within this library that will help you interact with the tool in a way that no other library does.
* Create your custom NSE (Nmap Scripting Engine) and parsing engine.
* Use utility functions to interact with ports and IP addresses on your own applications.

Installation
------------
The module requires an updated version of `Nmap <https://nmap.org/>`_ installed on the system. To install Nmapthon2, use the `pip` package manager::

    # If your pip command corresponds to Python 3
    pip install nmapthon2

    # If you use pip3 instead
    pip3 install nmapthon2

.. warning::

    Python 3.5+ is required.