"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='5.0.0',
    description='Protocol proxy (SAML/OIDC).',
    author='DIRG',
    author_email='satosa-dev@lists.sunet.se',
    license='Apache 2.0',
    url='https://github.com/SUNET/SATOSA',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    install_requires=[
        "pyop >= 3.0.1",
        "pysaml2",
        "pycryptodomex",
        "requests",
        "PyYAML",
        "gunicorn",
        "Werkzeug",
        "click",
        "pystache"
    ],
    extras_require={
        "ldap": ["ldap3"]
    },
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
    ],
    entry_points={
        "console_scripts": ["satosa-saml-metadata=satosa.scripts.satosa_saml_metadata:construct_saml_metadata"]
    }
)
