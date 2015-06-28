============
Installation
============

Dependencies
------------

``websnort`` relies on a user already having one or more functioning IDS
installations on their deployment host.

For help with installing `snort`_ please follow their documentation.

For help with installing `suricata`_ please follow their documentation.

For Linux operating systems, packaged versions of these applications may
already be available in your system software repository/library.

Install with Pip
----------------

The simplest way to install is using the `pip`_ package install utility.
This will ensure all python dependencies are downloaded/installed
appropriately::

	pip install websnort

It is recommended to use `virtualenv`_ to keep third-party packages isolated
from system python packages.  However, if installing system wide you will need
to run pip as root/sudo.
  
Run from Source
---------------

The latest code can be run directly by cloning the GitHub repository::

    git clone https://github.com/shendo/websnort.git

Configuration
-------------

The default config for `websnort` is setup to interface with a `snort`
deployment on Ubuntu/Debian, using the ruleset referenced by
*/etc/snort/snort.conf*.

To customise the setup you can override the websnort config file by creating
a new config file (in order of loading precedence):

 * ~/.websnort/websnort.conf
 * /etc/websnort/websnort.conf

Look at the example config files provided in *websnort/conf* for other common
configurations.

The config file format is as follows::

	[websnort]
	# Comma-separated list of config sections/instances to run
	ids = snort
	
	[snort]
	# python ids module name/type to use
	module = snort
	# name to give the ruleset in results
	ruleset = community
	# path to snort binary, will search path if not absolute
	path = snort
	# snort rules config file location
	config = /etc/snort/snort.conf
	# any additional command line args to include
	extra_args =  

Inbuilt Webserver
-----------------

``websnort`` uses the python ``bottle`` framework to provide its web interface.
This provides the ability to run a simple webserver from the command-line.

	usage: websnort [-h] [-H HOST] [-p PORT]
	
	optional arguments:
	  -h, --help            show this help message and exit
	  -H HOST, --host HOST  Web server Host address to bind to
	  -p PORT, --port PORT  Web server Port to bind to

By default the webserver will bind to all network interfaces and run on port
8080. To run on a different port number::

	websnort -p 8000

You will need to ensure the user that you are running the webserver as, has the
appropriate permissions to run snort/suricata from the command-line and can
read any applicable config files.

Python WSGI
-----------

``websnort`` also provides an entrypoint for interfacing with other webservers
that support python WSGI.

An example httpd config for apache could look something like the following::
	
	<VirtualHost *:80>
	
	    ServerName www.example.com
	    ServerAlias example.com
	    ServerAdmin webmaster@example.com
	
	    WSGIDaemonProcess example.com processes=3 threads=1 display-name=%{GROUP}
	    WSGIProcessGroup example.com
	
	    WSGIScriptAlias / /usr/lib/python/site-packages/websnort/web.py
	
	    <Directory /usr/lib/python/site-packages/websnort>
	    Order allow,deny
	    Allow from all
	    </Directory>
	
	</VirtualHost>

See `QuickConfigurationGuide`_ for more information on setting up modwsgi with Apache.

.. _pip: https://pip.pypa.io/en/latest/installing.html
.. _snort: https://www.snort.org/#get-started
.. _suricata: http://suricata-ids.org/docs/
.. _virtualenv: http://docs.python-guide.org/en/latest/dev/virtualenvs/
.. _QuickConfigurationGuide: https://code.google.com/p/modwsgi/wiki/QuickConfigurationGuide
