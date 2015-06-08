.. _index:

======================
Websnort Documentation
======================

Websnort is an *Open Source* web service for analysing pcap files with
intrusion detection systems such as ``snort`` and ``suricata``.

It allows multiple configurations of IDS setups and rulesets to be defined for
running against submitted samples.  Its primary use case is for analysing short
network captures from sandboxes and honeypots but can be used in any scenario
where there is a need to scan pcap samples.

This guide will explain how to deploy ``websnort`` in different environments
and example configurations.

Source code for ``websnort`` is hosted on `GitHub`_. Any bug reports or feature
requests can be made using GitHub's `issues system`_.

Features
========
* Support for Suricata and Snort
* Easy to extend support for other intrusion detection systems
* Parallel execution of multiple configurations and rulesets
* Simple Web API for integrating with other systems

Contents
========

.. toctree::
   :maxdepth: 1

   installation
   usage
   troubleshooting
   development

Issues
======

If you encounter problems with ``websnort``, please refer to the :ref:`troubleshooting`
section of the documentation.

.. _GitHub: https://github.com/shendo/websnort
.. _issues system: https://github.com/shendo/websnort/issues
 