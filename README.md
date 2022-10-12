# SATOSA

[![PyPI](https://img.shields.io/pypi/v/SATOSA.svg)](https://pypi.python.org/pypi/SATOSA)

A configurable proxy for translating between different authentication protocols
such as SAML2, OpenID Connect and OAuth2.


# Table of Contents

- [Installation](doc/README.md#installation)
  - [Docker](doc/README.md#docker)
  - [Manual installation](doc/README.md#manual-installation)
    - [Dependencies](doc/README.md#dependencies)
    - [Instructions](doc/README.md#instructions)
- [Configuration](doc/README.md#configuration)
  - [SATOSA proxy configuration: proxy_conf.yaml.example](doc/README.md#satosa-proxy-configuration-proxy_confyamlexample)
  - [Attribute mapping configuration: internal_attributes.yaml](doc/README.md#attribute-mapping-configuration-internal_attributesyaml)
    - [attributes](doc/README.md#attributes)
    - [user_id_from_attrs](doc/README.md#user_id_from_attrs)
    - [user_id_to_attr](doc/README.md#user_id_to_attr)
- [Plugins](doc/README.md#plugins)
  - [SAML2 plugins](doc/README.md#saml2-plugins)
    - [Metadata](doc/README.md#metadata)
    - [AuthnContextClassRef](doc/README.md#providing-authncontextclassref)
    - [Frontend](doc/README.md#saml2-frontend)
      - [Custom attribute release](doc/README.md#custom-attribute-release)
      - [Policy](doc/README.md#policy)
    - [Backend](doc/README.md#saml2-backend)
      - [Name ID Format](doc/README.md#name-id-format)
      - [Discovery service](doc/README.md#use-a-discovery-service)
      - [ForceAuthn option](doc/README.md#mirror-the-saml-forceauthn-option)
      - [Memorize IdP](doc/README.md#memorize-the-idp-selected-through-the-discovery-service)
  - [OpenID Connect plugins](doc/README.md#openid-connect-plugins)
    - [Frontend](doc/README.md#oidc-frontend)
    - [Backend](doc/README.md#oidc-backend)
    - [Social login plugins](doc/README.md#social-login-plugins)
      - [Google](doc/README.md#google)
      - [Facebook](doc/README.md#facebook)
  - [Dummy adapters](doc/README.md#dummy-adapters)
  - [Micro-services](doc/README.md#micro-services)
- [Generating proxy metadata](doc/README.md#generate-proxy-metadata)
- [Running the proxy application](doc/README.md#running-the-proxy-application)
- [External contributions](doc/README.md#external-contributions)


# Use cases

In this section a set of use cases for the proxy is presented.


## SAML2<->SAML2

There are SAML2 service providers for example Box which is not able to handle
multiple identity providers. For more information about how to set up,
configure and run such a proxy instance please visit [Single Service
Provider<->Multiple Identity providers](doc/one-to-many.md)

If an identity provider can not communicate with service providers in for
example a federation, they can convert requests and make the communication
possible.


## SAML2<->Social logins

This setup makes it possible to connect a SAML2 service provider to multiple
social media identity providers such as Google and Facebook. The proxy makes it
possible to mirror an identity provider by generating SAML2 metadata
corresponding to that provider and create dynamic endpoints which are connected to
a single identity provider.

For more information about how to set up, configure and run such a proxy
instance please read [SAML2<->Social logins](doc/SAML2-to-Social_logins.md)


## SAML2<->OIDC

The proxy is able to act as a proxy between a SAML2 service provider and a
OpenID connect provider [SAML2<->OIDC](doc/saml2-to-oidc.md)

# Contact

If you have any questions regarding operations/deployment of SATOSA please use
the satosa-users [mailing list](https://lists.sunet.se/postorius/lists/idpy-discuss.lists.sunet.se/).
