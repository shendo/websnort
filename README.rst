websnort
========

Web submission api for analysing pcap files with ``snort``.

Overview
--------

``websnort`` provides a web interface for user and system submission of packet
capture files to run against a ``snort`` IDS instance.  Alerts and logs are
returned as results.

If you are after a web interface for monitoring a running ``snort`` instance,
see http://www.snort.org/snort-downloads/additional-downloads instead.

Getting Started
---------------

**Ubuntu**

Install ``snort`` if needed: ::

    sudo apt-get install snort
    
*Optional* Disable running snort service if only required for this web api: ::

    sudo service snort stop
    sudo update.rc disable snort
    
Install using ``pip``: ::

	sudo pip install websnort

Start the ``websnort`` web server on the default port: ::

	websnort

Browse to server:8080 and submit a pcap file for analysis.

Issues
------

Source code for ``websnort`` is hosted on `GitHub`_. Any bug reports or feature
requests can be made using GitHub's `issues system`_.

.. _GitHub: https://github.com/shendo/websnort
.. _issues system: https://github.com/shendo/websnort/issues
