# SATOSA
[![Build Status](https://travis-ci.org/its-dirg/SATOSA.svg?branch=travis)](https://travis-ci.org/its-dirg/SATOSA)
[![PyPI](https://img.shields.io/pypi/v/SATOSA.svg)](https://pypi.python.org/pypi/SATOSA)

# Table of Contents

- [Installation](doc/README.md#installation)
    - [Dependencies](doc/README.md#dependencies)
    - [Instructions](doc/README.md#install_instructions)
- [Configuration](doc/README.md#configuration)
    - [SATOSA proxy configuration: proxy_conf.yaml.example](doc/README.md#proxy_conf)
        - [Additional services](doc/README.md#additional_service)
    - [Attribute mapping configuration: internal_attributes.yaml](doc/README.md#attr_map)
        - [attributes](doc/README.md#attributes)
        - [user_id_from_attr](doc/README.md#user_id_from_attr)
        - [user_id_to_attr](doc/README.md#user_id_to_attr)
        - [hash](doc/README.md#hash)
- [Plugins](doc/README.md#plugins)
    - [SAML2 plugins](doc/README.md#saml_plugin)
        - [Metadata](doc/README.md#metadata)
        - [Frontend](doc/README.md#frontend)
        - [Backend](doc/README.md#backend)
            - [Name ID Format](doc/README.md#name_id)
    - [OpenID Connect plugins](doc/README.md#openid_plugin)
        - [Backend](doc/README.md#backend)
    - [Social login plugins](doc/README.md#social_plugins)
        - [Google](doc/README.md#google)
        - [Facebook](doc/README.md#facebook)
- [SAML metadata](doc/README.md#saml_metadata)
    - [Generate backend metadata](doc/README.md#backend_metadata)
- [Running the proxy application](doc/README.md#run)


## Use cases

### Single Service Provider<->Multiple Identity providers 
There are SAML2 service providers for example Box which is not able to handle multiple identity 
providers. For more information about how to set up, configure and run such a proxy instance 
please visit [Single Service Provider<->Multiple Identity providers](doc/one-to-many.md)

### SAML2<->Social logins
This setup makes it possible to connect a SAML2 service provider to multiple social media identity 
providers such as Goolgle, Facebook. The proxy makes it possible to mirror a identity provider by 
generating SAML2 metadata corresponding that provider and create dynamic endpoint which 
are connected to a single identity provider.
For more information about how to set up, configure and run such a proxy instance please visit 
[SAML2<->Social logins](doc/SAML2-to-Social_logins.md)

### SAML2<->OIDC
The proxy is able to act as a proxy between a SAML2 service provider and a OpenID connect provider 
[SAML2<->OIDC](doc/saml2-to-oidc.md)


### SAML2<->SAML2
This could be used in order to connect two different SAML2 implementations which normally could not 
communicate.
[SAML2<->SAML2](doc/saml2-to-saml2.md)
