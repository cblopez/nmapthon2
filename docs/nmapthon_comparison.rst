Nmapthon2 vs Nmapthon
=====================

There are several enhancements and reasons why this library has been released as a second Nmapthon version, rather than 
keep evolving the already existing library. Here are some of those reasons that you will quicly identify once you 
start using this new version:

* **Usability**: As opposed to the previous version, Nmapthon2 comes with several built-in facilities that will help to retrieve, iterate and interact with scan results in a more Pythonic way.
* **Simplicity**: Some functionalities, like merging, have been deleted, which where nice to have but really unnecesary.
* **More Nmap parsing**: This new version parses a lot more information from the Nmap scan output compared with the original library, with a much cleaner code.
* **Better design**: From the usability perspective, you should only need to instantiate one single "Nmap scanner" and reuse it any number of times you would like. The original library would make you alter the scanner object properties or instantiate a new scanner, which is fine, but not optimal.
* **Customization**: Several options have been added to help with Nmap execution from the Python code:
    * Get async scans completion percentage.
    * Resume Nmap scans from its XML file.
    * Choose the nmap binary file.
    * Execute Nmap with a raw string containing the options, ports and targets.
    * Get the Nmap output right in your result object with almost all supported formats by the tool (XML, normal, grep).
* **Full Object-Oriented**: Instead of using a wide variety of methods from a single instance, it is easier to separate the output information into different inter-related objects, with more properties and less methods. Tools implementing Nmapthon2 will end up with a much cleaner code than before.
* **NSE enhancements**: The original ``PyNSEEngine`` was a good idea, but it felt quite annoying to only be able to use it as Flask (one single file with decorated functions), so this time Nmapthon2 comes with 3 different ways to register NSE scripts, with additional new functionalities.