# SATOSA
[![Build Status](https://travis-ci.org/IdentityPython/SATOSA.svg?branch=travis)](https://travis-ci.org/IdentityPython/SATOSA)
[![PyPI](https://img.shields.io/pypi/v/SATOSA.svg)](https://pypi.python.org/pypi/SATOSA)

A configurable proxy for translating between different authentication protocols such as SAML2, 
OpenID Connect and OAuth2.

# Table of Contents

- [Installation](doc/README.md#installation)
    - [Docker](doc/README.md#docker)
    - [Manual installation](doc/README.md#manual_installation)
        - [Dependencies](doc/README.md#dependencies)
        - [Instructions](doc/README.md#install_instructions)
- [Configuration](doc/README.md#configuration)
    - [SATOSA proxy configuration: proxy_conf.yaml.example](doc/README.md#proxy_conf)
        - [Additional services](doc/README.md#additional_service)
    - [Attribute mapping configuration: internal_attributes.yaml](doc/README.md#attr_map)
        - [attributes](doc/README.md#attributes)
        - [user_id_from_attrs](doc/README.md#user_id_from_attrs)
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
- [Running the proxy application](doc/README.md#run)


# Use cases
In this section a set of use cases for the proxy is presented. 

## SAML2<->SAML2
There are SAML2 service providers for example Box which is not able to handle multiple identity 
providers. For more information about how to set up, configure and run such a proxy instance 
please visit [Single Service Provider<->Multiple Identity providers](doc/one-to-many.md)

If an identity provider can not communicate with service providers in for example a federation the 
can convert request and make the communication possible.

## SAML2<->Social logins
This setup makes it possible to connect a SAML2 service provider to multiple social media identity 
providers such as Google and Facebook. The proxy makes it possible to mirror a identity provider by 
generating SAML2 metadata corresponding that provider and create dynamic endpoint which 
are connected to a single identity provider.
For more information about how to set up, configure and run such a proxy instance please visit 
[SAML2<->Social logins](doc/SAML2-to-Social_logins.md)

## SAML2<->OIDC
The proxy is able to act as a proxy between a SAML2 service provider and a OpenID connect provider 
[SAML2<->OIDC](doc/saml2-to-oidc.md)

# Contact
If you have any questions regarding operations/deployment of SATOSA please use the satosa-users [mailing list](https://lists.sunet.se/listinfo/satosa-users).
