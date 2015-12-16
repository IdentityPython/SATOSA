#!/usr/bin/env python

"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='0.4.1',
    description='Protocol proxy (SAML/OIDC).',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='Apache 2.0',
    url='https://github.com/its-dirg/SATOSA',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    scripts=["tools/make_satosa_saml_metadata.py"],
    install_requires=[
        "pluginbase",
        "future",
        "oic",
        "pyjwkest",
        "pysaml2 >= 4.0.0",
        "requests",
        "PyYAML",
        "pycrypto",
        "gunicorn",
        "Werkzeug"
    ],
    zip_safe=False,
)
