"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='1.0.4',
    description='Protocol proxy (SAML/OIDC).',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='Apache 2.0',
    url='https://github.com/its-dirg/SATOSA',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    scripts=["tools/make_satosa_saml_metadata.py"],
    install_requires=[
        "oic==0.8.4.0",
        "pyjwkest==1.1.5",
        "pysaml2==4.0.3",
        "requests==2.9.1",
        "PyYAML==3.11",
        "gunicorn==19.4.1",
        "Werkzeug==0.11.2",
    ],
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
    ]
)
