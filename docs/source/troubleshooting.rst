.. _troubleshooting:

===============
Troubleshooting
===============

.. _permission_denied:

Why do I get a permission denied error from websnort?
-----------------------------------------------------

You need to ensure that snort/suricata can run as the same user running the
web application.  In particular check that all config files are readable by the
web user.  On Ubuntu recent packages of snort deploy */etc/snort/snort.conf* as
root readable only.

If this is the case try::

 sudo chmod a+r /etc/snort/snort.conf
 
It is also worth testing without using the web application, by attempting to
run the snort/suricata command-line as the web user, manually on the
command-line to verify it produces the expected results.

For example::

 snort -r /tmp/test.pcap -c /etc/snort/snort.conf -A console -l /tmp

.. _no_alerts:

Why doesn't websnort show the alerts I expect?
----------------------------------------------

If you expect the pcap you are submitting to generate alerts and it doesn't,
verify that the IDS generates the expected alerts from the command-line as the
webapp user.

For example::

 snort -r /tmp/test.pcap -c /etc/snort/snort.conf -A console -l /tmp
 
If this is not working you may want to disable checksum validation for the IDS,
especially if the pcaps were generated from a virtual network/sandbox or replay
tool.

For example, in */etc/snort/snort.conf* add::

 validate_checksums off

Or in */etc/suricata/suricata.yaml* change::

 stream:
   memcap: 128mb
   checksum-validation: no
 
If your pcaps have some unusual VLAN tagging and you are running Suricata, you
may want to try disabling VLAN tracking in the sessionisation.

For example in */etc/suricata/suricata.yaml* change::

 vlan:
   use-for-tracking: false
 
.. _other_issues:

Websnort still doesn't work what should I do?
---------------------------------------------

If you have read through the relevant sections of the documentation but
are still having problems, please raise an issue on the project's
`issue tracker`_ and someone may be able to assist.

.. _issue tracker: https://github.com/shendo/websnort/issues

