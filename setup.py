"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='8.6.0',
    description='Protocol proxy (SAML/OIDC).',
    author='DIRG',
    author_email='satosa-dev@lists.sunet.se',
    license='Apache 2.0',
    url='https://github.com/SUNET/SATOSA',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    python_requires=">=3.11",
    install_requires=[
        "pyop >= v3.4.0",
        "pysaml2 >= 6.5.1",
        "pycryptodomex",
        "requests",
        "PyYAML",
        "gunicorn",
        "Werkzeug",
        "click",
        "chevron",
        "cookies-samesite-compat",
    ],
    extras_require={
        "ldap": ["ldap3"],
        "pyop_mongo": ["pyop[mongo]"],
        "pyop_redis": ["pyop[redis]"],
        "idpy_oidc_backend": ["idpyoidc >= 2.1.0"],
    },
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
    entry_points={
        "console_scripts": ["satosa-saml-metadata=satosa.scripts.satosa_saml_metadata:construct_saml_metadata"]
    }
)
