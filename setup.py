"""
setup.py
"""

from setuptools import setup, find_packages

setup(
    name='SATOSA',
    version='2.0.0',
    description='Protocol proxy (SAML/OIDC).',
    author='DIRG',
    author_email='dirg@its.umu.se',
    license='Apache 2.0',
    url='https://github.com/its-dirg/SATOSA',
    packages=find_packages('src/'),
    package_dir={'': 'src'},
    install_requires=[
        "oic==0.8.4.0",
        "pyjwkest==1.1.5",
        "pysaml2==4.0.3",
        "requests==2.9.1",
        "PyYAML==3.11",
        "gunicorn==19.4.1",
        "Werkzeug==0.11.2",
        "click==6.6"
    ],
    zip_safe=False,
    classifiers=[
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.4",
    ],
    entry_points={
        "console_scripts": ["satosa-saml-metadata=satosa.scripts.satosa_saml_metadata:construct_saml_metadata"]
    }
)
