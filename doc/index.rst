.. SATOSA documentation master file, created by
   sphinx-quickstart on Mon Nov  2 09:57:18 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to SATOSA's documentation!
==================================

Contents:

.. toctree::
   :maxdepth: 2



Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

Generate metadata
-----------------

To generate metadata for the SATOSA frontends and backends based on Saml2, use the script **tools/make_saml_metadata.py**.
This will generate one saml2 metadata file for each frontend/backend. Use the proxy config file as parameter
to the script.

Example::

   python3 make_saml_metadata.py proxy_config.py

