#!/usr/bin/env python

"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='0.0.1.2',
    description='',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='Apache 2.0',
    url='',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    scripts=["tools/make_saml_metadata.py"],
    install_requires=["pluginbase",
                      "future",
                      # "oic",
                      "pyjwkest",
                      # "pysaml2 >= 3.0.2",
                      "requests",
                      "PyYAML",
                      "pycrypto",
                      ],
    zip_safe=False,
)
