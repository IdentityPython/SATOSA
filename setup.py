#!/usr/bin/env python

"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='vopaas_proxy',
    version='0.0.1',
    description='',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='Apache 2.0',
    url='',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    classifiers=['Development Status :: 4 - Beta',
                 'License :: OSI Approved :: Apache Software License',
                 'Topic :: Software Development :: Libraries :: Python Modules',
                 'Programming Language :: Python :: 2.7',
                 'Programming Language :: Python :: 3.4'],
    install_requires=["pysaml2 >= 3.0.0"],
    zip_safe=False,
)
