NSE
===

.. toctree::
    :titlesonly:
    :maxdepth: 1

    nse_host_port_scripts
    nse_flask
    nse_callback

One of the greatest things of Nmapthon2 is its built-in custom ``NSE``. This object allows programmers to extend the already existing Nmap's NSE with Python functions and methods implementing their own
security checks. Addtionally to custom Python scripts, this object allows us to register parsers, which are functions that automatically parse Nmap's NSE scripts output.
This idea comes from the original Nmapthon library, but it has been greatly improved for this version. Although we will cover all types of usage, you should know that there are 3 ways of registering
functions into an ``NSE`` object (doesnt matter if its a host/port script or a parser).

* In a Flask-like way, registering functions with decorators. Really usefull when you have one-file scripts.
* Registering functions statically, which is defining the function anywhere in your code for later registering them as callback functions with one line of code.
* Create your own NSE implementation with an Object-Orieted approach, usefull for bigger applications and for those of you who, like me, love OOP.

.. important::

    Depening on the NSE script, Nmap may execute it before, after or during the port scan. Nmapthon2 cannot choose that, so all the scripts will be executed 
    **after** scanning all the targets.