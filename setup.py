#!/usr/bin/env python

"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='1.0.0',
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
        "oic==0.8.3",
        "pyjwkest",
        "pysaml2==4.0.3",
        "requests",
        "PyYAML",
        "gunicorn",
        "Werkzeug"
    ],
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
    ]
)
