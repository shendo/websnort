===========
Development
===========

If you are interested in contributing to the project please read through
the following sections.

Websnort API
============

The codebase is quite simple with the execution logic defined in
`websnort.runner`: 

.. automodule:: websnort.runner
   :members: is_pcap, run
   :undoc-members:

Bottle App
----------

And the web handling, ``bottle`` routes defined in `websnort.web`:

.. automodule:: websnort.web
   :members: home, api_submit, submit_and_render
   :undoc-members:

IDS Plugins
-----------

Interfacing with other IDS systems is possible by implementing a new plugin.
The plugin can either be statically registered in *websnort.plugins.registry*
or hooked in at install time by defining the correct setuptools entrypoint in
your project.

See `websnort.runner.IDSRunner` for expected class API. 

.. automodule:: websnort.plugins
   :members: IDSRunner
   :undoc-members:

Pull Requests
=============

If you wish to contribute a bug fix or feature, please open a pull request on
the Github project page for discussion/review.  While not strictly enforced,
the code-style should follow python `PEP8`_ standard.

Licensing
=========

All contributions to the project are to be made under the terms of the GNU
Public License v3.

Copyright of any contributions remain the property of the original authors.
If there are significant community contributions to the project we will look
at updating the copyright headers of the project to make it clear that the
project copyright and ownership is that of all said community developers.

Issues
======

If you have encountered a problem or need help in some aspect of the project
you are probably not alone.  Please raise an issue in the `issue tracker`_ on
the project's Github page so other users can benefit from the answers too.

.. _PEP8: https://www.python.org/dev/peps/pep-0008/
.. _issue tracker: https://github.com/shendo/websnort/issues
