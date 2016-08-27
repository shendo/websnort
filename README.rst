websnort
========

Web service for analysing pcap files with intrusion detection systems such as
``snort`` and ``suricata``.

|build_status| |pypi_version|

Overview
--------

``websnort`` provides a web interface for user and system submission of packet
capture files to run against IDS instances.  Alerts and details from the analysis
are returned as results.

If you are after a web interface for monitoring a live ``snort`` instance,
see https://www.snort.org/downloads#additional-downloads instead.

While originally developed specifically for ``snort``.  Recent releases support
a flexible IDS plugin system which also supports ``suricata`` out of the box.

``websnort`` can be configured to run the same submitted packet capture
against any number of IDS instances, configs and rulesets.  This allows broader
coverage and comparison between installs and rule versions.

Getting Started
---------------

**Ubuntu**

Install ``snort`` if needed: ::

    sudo apt-get install snort
    
*Optional* Disable running snort service if only required for this web api: ::

    sudo service snort stop
    sudo update-rc.d snort disable

On recent ubuntu/debian releases the default *snort.conf* is not world readable.  Unless 
planning to run the web service as root (not recommended) you will need to modify the
permissions, for example: ::

	sudo chmod a+r /etc/snort/snort.conf

Install web service using ``pip``: ::

	sudo pip install websnort

Start the ``websnort`` web server on the default port: ::

	websnort

Browse to http://server:8080 and submit a pcap file for analysis.

Navigate to http://server:8080/api for details of provided json web api.

Documentation
-------------

Full project documentation can be found on `readthedocs`_.

Issues
------

Source code for ``websnort`` is hosted on `GitHub`_. Any bug reports or feature
requests can be made using GitHub's `issues system`_.

.. _GitHub: https://github.com/shendo/websnort
.. _issues system: https://github.com/shendo/websnort/issues
.. _readthedocs: https://websnort.readthedocs.org

.. |build_status| image:: https://secure.travis-ci.org/shendo/websnort.png?branch=master
   :target: https://travis-ci.org/shendo/websnort
   :alt: Current build status

.. |pypi_version| image:: https://img.shields.io/pypi/v/websnort.svg
   :target: https://pypi.python.org/pypi/websnort
   :alt: Latest PyPI version
