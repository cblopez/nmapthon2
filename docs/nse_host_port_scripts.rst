Host scripts, port scripts and parsers
======================================

Depending on if you are registering a host script or a port script, the function being defined must be different. In this sub-section 
you will not learn how to register any function into the ``NSE``, but the requirements of those functions. Rules are quite simple:

* **Host scripts** functions must recieve one parameter, which will be the ``Host`` object reference that the function will be targetting. They must return the value to be assigned as script output:

.. code-block:: python

    def my_custom_host_script(host):

        # I do my things here...
        # Since "host" is a Host instance, you can use all of its properties and methods.

        return None

* **Port scripts** functions must recieve three parameters, which will be the ``Host``, ``Port`` and ``Service`` object references, respectively, that the function will be targetting. They must return the value to be assigned as script output:

.. code-block:: python

    def my_custom_port_script(host, port, service):

        # I do my things here....
        # Same as above, you can use any property and method from this instances.

        return None

* NSE scripts that fail their execution do not appear in scan results. If you want to emulate this behaviour, your function shoud raise a ``StopExecution`` error.

.. code-block:: python

    from nmapthon2.exceptions import StopExecution

    def another_custom_host_script(host):

        if True:
            raise StopExecution # This script would not appear in the results

* **Parsers** can be for individual scripts or every single script (usefull for decoding, deleting/substituding characters...), but both type of parsers are defined the same way. Parser functions must recieve one unique parameter, which is the NSE script output and must return the parsed output.

.. code-block:: python

    def parser_example(output):

        # I do my parsing here, like for example...
        output = output.strip()

        # I must return the final parsed text
        return output
