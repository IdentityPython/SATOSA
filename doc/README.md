This document describes how to install and configure the SATOSA proxy.

<!-- ![](doc/images/satosa_proxy_internals.png "SATOSA overview image") -->

# Installation

## <a name="docker" style="color:#000000">Docker</a>
A pre-built Docker image is accessible at the [Docker Hub](https://hub.docker.com/r/satosa/), and is the
recommended ways of running the proxy.

## <a name="manual_installation" style="color:#000000">Manual installation</a>

### <a name="dependencies" style="color:#000000">Dependencies</a>
SATOSA requires Python 3.4 (or above), and the following packages on Ubuntu:
```
apt-get install libffi-dev libssl-dev xmlsec1
````

### <a name="install_instructions" style="color:#000000">Instructions</a>
1. Download the SATOSA proxy project as a [compressed archive](https://github.com/SUNET/SATOSA/releases)
   and unpack it to `<satosa_path>`.

1. Install the application:

   ```bash
   pip install <satosa_path>
   ```

Alternatively the application can be installed directly from PyPI (`pip install satosa`), or the [Docker image](https://hub.docker.com/r/satosa/) can be used.

# Configuration
All default configuration files, as well as an example WSGI application for the proxy, can be found
in the [example directory](../example).

## <a name="proxy_conf" style="color:#000000">SATOSA proxy configuration</a>: `proxy_conf.yaml.example`
| Parameter name | Data type | Example value | Description |
| -------------- | --------- | ------------- | ----------- |
| `BASE` | string | `https://proxy.example.com` | base url of the proxy |
| `COOKIE_STATE_NAME` | string | `satosa_state` | name of cooke SATOSA uses for preserving state between requests |
| `STATE_ENCRYPTION_KEY` | string | `52fddd3528a44157` | key used for encrypting the state cookie, will be overriden by the environment variable `SATOSA_STATE_ENCRYPTION_KEY` if it is set |
| `INTERNAL_ATTRIBUTES` | string | `example/internal_attributes.yaml` | path to attribute mapping
| `CUSTOM_PLUGIN_MODULE_PATHS` | string[] | `[example/plugins/backends, example/plugins/frontends]` | list of directory paths containing any front-/backend plugin modules |
| `BACKEND_MODULES` | string[] | `[openid_connect_backend.yaml, saml2_backend.yaml]` | list of plugin configuration file paths, describing enabled backends |
| `FRONTEND_MODULES` | string[] | `[saml2_frontend.yaml, openid_connect_frontend.yaml]` | list of plugin configuration file paths, describing enabled frontends |
| `MICRO_SERVICES` | string[] | `[statistics_service.yaml]` | list of plugin configuration file paths, describing enabled microservices |
| `USER_ID_HASH_SALT` | string | `61a89d2db0b9e1e2` | salt used when creating the persistent user identifier, will be overriden by the environment variable `SATOSA_USER_ID_HASH_SALT` if it is set |
| `LOGGING` | dict | see [Python logging.conf](https://docs.python.org/3/library/logging.config.html) | optional configuration of application logging |


## <a name="attr_map" style="color:#000000">Attribute mapping configuration:</a> `internal_attributes.yaml`

### attributes
The values directly under the `attributes` key are the internal attribute names.
Every internal attribute has a map of profiles, which in turn has a list of
external attributes names which should be mapped to the internal attributes.

If multiple external attributes are specified under a profile, the proxy will
store all attribute values from the external attributes as a list in the
internal attribute.

Sometimes the external attributes are nested/complex structures. One example is
the [address claim in OpenID connect](http://openid.net/specs/openid-connect-core-1_0.html#AddressClaim)
which consists of multiple sub-fields, e.g.:
```json
"address": {
  "formatted": "100 Universal City Plaza, Hollywood CA 91608, USA",
  "street_address": "100 Universal City Plaza",
  "locality": "Hollywood",
  "region": "CA",
  "postal_code": "91608",
  "country": "USA",
}
```

In this case the proxy accepts a dot-separated string denoting which external
attribute to use, e.g. `address.formatted` will access the attribute value
`"100 Universal City Plaza, Hollywood CA 91608, USA"`.

**Example**
```yaml
attributes:
  mail:
    openid: [email]
    saml: [mail, emailAdress, email]
  address:
    openid: [address.formatted]
    saml: [postaladdress]
```

This example defines two attributes, `mail` and `address`, internal to the proxy. These attributes will be accessible to
any plugin (i.e. front- and backends) in the proxy.

Each internal attribute has a mapping for two different *profiles*, `openid`and `saml`. The mapping between received
attributes (in the proxy backend) <-> internal <-> returned attributes (from the proxy frontend) is defined as:

* Any plugin using the `openid` profile will use the attribute value from
  `email` delivered from the target provider as the value for `mail`.
* Any plugin using the `saml` profile will use the attribute value from `mail`,
  `emailAdress` and `email` depending on which attributes are delivered by the
  target provider as the value for `mail`.
* Any plugin using the `openid` profile will use the attribute value under the
  key `formatted` in the `address` attribute delivered by the target provider.
* Any plugin using the `saml` profile will use the attribute value from `postaladdress`
  delivered from the target provider as the value for `address`.


### user_id_from_attrs
The user identifier generated by the backend module can be overridden by
specifying a list of internal attribute names under the `user_id_from_attrs` key.
The attribute values of the attributes specified in this list will be
concatenated and hashed to be used as the user identifier.


### user_id_to_attr
To store the user identifier in a specific internal attribute, the internal
attribute name can be specified in `user_id_to_attr`.
When the [ALService](https://github.com/its-dirg/ALservice) is used for account
linking, the `user_id_to_attr` configuration parameter should be set, since that
service will overwrite the user identifier generated by the proxy.


### hash
The proxy can hash any attribute value (e.g., for obfuscation) before passing
it on to the client. The `hash` key should contain a list of all attribute names
for which the corresponding attribute values should be hashed before being
returned to the client.


## Plugins
The authentication protocol specific communication is handled by different plugins,
divided into frontends (receiving requests from clients) and backends (sending requests
to target providers).

### Common plugin configuration parameters
Both `name` and `module` must be specified in all plugin configurations (frontends, backends, and micro services).
The `name` must be unique to ensure correct functionality, and the `module` must be the fully qualified name of an
importable Python module.

### <a name="saml_plugin" style="color:#000000">SAML2 plugins</a>

Common configuration parameters:

| Parameter name | Data type | Example value | Description |
| -------------- | --------- | ------------- | ----------- |
| `organization` | dict | `{display_name: Example Identities, name: Example Identities Organization, url: https://www.example.com}` | information about the organization, will be published in the SAML metadata |
| `contact_person` | dict[] | `{contact_type: technical, given_name: Someone Technical, email_address: technical@example.com}` | list of contact information, will be published in the SAML metadata |
| `key_file` | string | `pki/key.pem` | path to private key used for signing(backend)/decrypting(frontend) SAML2 assertions |
| `cert_file` | string | `pki/cert.pem` | path to certificate for the public key associated with the private key in `key_file` |
| `metadata["local"]` | string[] | `[metadata/entity.xml]` | list of paths to metadata for all service providers (frontend)/identity providers (backend) communicating with the proxy |
| `attribute_profile` | string | `saml` | attribute profile to use for mapping attributes from/to response
| `entityid_endpoint` | bool | `true` | whether `entityid` should be used as a URL that serves the metadata xml document
| `acr_mapping` | dict | `None` | custom Authentication Context Class Reference

The metadata could be loaded in multiple ways in the table above it's loaded from a static
file by using the key "local". It's also possible to load read the metadata from a remote URL.

**Examples:**

Metadata from local file:

    "metadata":
        local: [idp.xml]

Metadata from remote URL:

    "metadata": {
        "remote":
            - url:https://kalmar2.org/simplesaml/module.php/aggregator/?id=kalmarcentral2&set=saml2
              cert:null
    }

For more detailed information on how you could customize the SAML entities,
see the
[documentation of the underlying library pysaml2](https://github.com/rohe/pysaml2/blob/master/docs/howto/config.rst).


##### Providing `AuthnContextClassRef`

SAML2 frontends and backends can provide a custom (configurable) *Authentication Context Class Reference*.
For the frontend this is defined in the `AuthnStatement` of the authentication response, while,
for the backend this is defined in the `AuthnRequest`.

This can be used to describe for example the Level of Assurance, as described for example by [eIDAS](https://ec.europa.eu/cefdigital/wiki/jdisplay/CEFDIGITAL/eIDAS+Profile?preview=/46992719/47190128/eIDAS%20Message%20Format_v1.1-2.pdf).

The `AuthnContextClassRef`(ACR) can be specified per target provider in a mapping under the
configuration parameter `acr_mapping`. The mapping must contain a default ACR value under the key `""`
(empty string), each other ACR value specific per target provider is specified with key-value pairs, where the
key is the target providers identifier (entity id for SAML IdP behind SAML2 backend, authorization endpoint
URL for OAuth AS behind OAuth backend, and issuer URL for OpenID Connect OP behind OpenID Connect backend).

If no `acr_mapping` is provided in the configuration, the ACR received from the backend plugin will
be used instead. This means that when using a SAML2 backend, the ACR provided by the target
provider will be preserved, and when using a OAuth or OpenID Connect backend, the ACR will be
`urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified`.

**Example**

    config:
        [...]
        acr_mapping:
            "": default-LoA
            "https://accounts.google.com": LoA1


#### Frontend

The SAML2 frontend act as a SAML Identity Provider (IdP), accepting
authentication requests from SAML Service Providers (SP). The default
configuration file can be found [here](../example/plugins/frontends/saml2_frontend.yaml.example).

The SAML2 frontend comes in two different flavors:

The **SAMLMirrorFrontend** module mirrors each target provider as a separate entity in the SAML metadata.
In this proxy this is handled with dynamic entity id's, encoding the target provider.
This allows external discovery services to present the mirrored providers transparently, as separate entities
in its UI. The following flow diagram shows the communcation:

`SP -> optional discovery service -> selected proxy SAML entity -> target IdP`


The **SAMLFrontend** module acts like a single IdP, and hides all target providers. This enables the proxy to support
SP's which only support communication with a single IdP, while the proxy will seamlessly communicate with multiple
target providers. The metadata for the published IdP will contain one *Single Sign On Location* for each target
provider.

The following flow diagram shows the communication:

`SP -> proxy SAML SSO location -> target IdP`

For the simple case where an SP does not support discovery it's also possible to delegate the discovery to the
`SAMLBackend` (see below), which would enable the following communication flow:

`SP -> SAMLFrontend -> SAMLBackend -> discovery to select target IdP -> target IdP`


##### Custom attribute release
In addition to respecting for example entity categories from the SAML metadata, the SAML frontend can also further
restrict the attribute release with the `custom_attribute_release` configuration parameter based on the SP entity id.

To exclude any attribute, just include its friendly name in the exclude list per SP.

In the following example the given name is never released from the IdP with entity id `"idp-entity-id1"` to the SP
with entity id `"sp-entity-id1"`:

```yaml
config:
    idp_config: [...]
    custom_attribute_release:
        idp-entity-id1
            sp-entity-id1:
                exclude: ["givenName"]
```

The custom_attribute_release mechanism supports defaults based on idp and sp entity Id by specifying "" or "default"
as the key in the dict. For instance in order to exclude givenName for any sp or idp do this:

```yaml
config:
    idp_config: [...]
    custom_attribute_release:
        "default":
            "":
                exclude: ["givenName"]
```

#### Policy

Some settings related to how a SAML response is formed can be overriden on a per-instance or a per-SP
basis. This example summarizes the most common settings (hopefully self-explanatory) with their defaults:

```yaml
config:
    idp_config:
        service:
            idp:
                policy:
                    default:
                        sign_response: True
                        sign_assertion: False
                        sign_alg: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
                        digest_alg: "http://www.w3.org/2001/04/xmlenc#sha256"
                    <sp entityID>:
                        ...
```

Overrides per SP entityID is possible by using the entityID as a key instead of the "default" key
in the yaml structure. The most specific key takes presedence. If no policy overrides are provided
the defaults above are used.


#### Backend
The SAML2 backend act as a SAML Service Provider (SP), making authentication
requests to SAML Identity Providers (IdP). The default configuration file can be
found [here](../example/plugins/backends/saml2_backend.yaml.example).

##### <a name="name_id" style="color:#000000">Name ID Format</a>
The SAML backend can indicate which *Name ID* format it wants by specifying the key
`name_id_format` in the SP entity configuration in the backend plugin configuration:

 ```yaml
 config:
   sp_config:
     service:
       sp:
        name_id_format: urn:oasis:names:tc:SAML:2.0:nameid-format:transient
 ```

##### Use a discovery service
To allow the user to choose which target provider they want to authenticate with, the configuration
parameter `disco_srv`, must be specified if the metadata given to the backend module contains more than one IdP:

```yaml
config:
  sp_config: [...]
    disco_srv: http://disco.example.com
```

### <a name="openid_plugin" style="color:#000000">OpenID Connect plugins</a>

#### Backend
The OpenID Connect backend acts as an OpenID Connect Relying Party (RP), making
authentication requests to OpenID Connect Provider (OP). The default
configuration file can be found [here](../example/plugins/backends/openid_backend.yaml.example).

The example configuration assumes the OP supports [discovery](http://openid.net/specs/openid-connect-discovery-1_0.html)
and [dynamic client registration](https://openid.net/specs/openid-connect-registration-1_0.html).
When using an OP that only supports statically registered clients, see the
[default configuration for using Google as the OP](../example/plugins/backends/google_backend.yaml.example)
and make sure to provide the redirect URI, constructed as described in the
section about Google configuration below, in the static registration.


#### Frontend
The OpenID Connect frontend acts as and OpenID Connect Provider (OP), accepting requests from OpenID
Connect Relying Parties (RPs). The default configuration file can be found
[here](../example/plugins/frontends/openid_connect_frontend.yaml.example).

As opposed to the other plugins, this plugin is NOT stateless (due to the nature of OpenID Connect using any other
flow than "Implicit Flow"). However, the frontend supports using a MongoDB instance as its backend storage, so as long
that's reachable from all machines it should not be a problem.

The configuration parameters available:
* `signing_key_path`: path to a RSA Private Key file (PKCS#1). MUST be configured.
* `db_uri`: connection URI to MongoDB instance where the data will be persisted, if it's not specified all data will only
   be stored in-memory (not suitable for production use).
* `provider`: provider configuration information. MUST be configured, the following configuration are supported:
    * `response_types_supported` (default: `[id_token]`): list of all supported response types, see [Section 3 of OIDC Core](http://openid.net/specs/openid-connect-core-1_0.html#Authentication).
    * `subject_types_supported` (default: `[pairwise]`): list of all supported subject identifier types, see [Section 8 of OIDC Core](http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes)
    * `scopes_supported` (default: `[openid]`): list of all supported scopes, see [Section 5.4 of OIDC Core](http://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
    * `client_registration_supported` (default: `No`): boolean whether [dynamic client registration is supported](https://openid.net/specs/openid-connect-registration-1_0.html).
        If dynamic client registration is not supported all clients must exist in the MongoDB instance configured by the `db_uri` in the `"clients"` collection of the `"satosa"` database.
        The registration info must be stored using the client id as a key, and use the parameter names of a [OIDC Registration Response](https://openid.net/specs/openid-connect-registration-1_0.html#RegistrationResponse).
    * `authorization_code_lifetime`: how long authorization codes should be valid, see [default](https://github.com/SUNET/pyop#token-lifetimes)
    * `access_token_lifetime`: how long access tokens should be valid, see [default](https://github.com/SUNET/pyop#token-lifetimes)
    * `refresh_token_lifetime`: how long refresh tokens should be valid, if not specified no refresh tokens will be issued (which is [default](https://github.com/SUNET/pyop#token-lifetimes))
    * `refresh_token_threshold`: how long before expiration refresh tokens should be refreshed, if not specified refresh tokens will never be refreshed (which is [default](https://github.com/SUNET/pyop#token-lifetimes))

The other parameters should be left with their default values.

### <a name="social_plugins" style="color:#000000">Social login plugins</a>
The social login plugins can be used as backends for the proxy, allowing the
proxy to act as a client to the social login services.

#### Google
The default configuration file can be
found [here](../example/plugins/backends/google_backend.yaml.example).

The only parameters necessary to configure is the credentials,
(`client_id` and `client_secret`) issued by Google. See [OAuth 2.0 credentials](https://developers.google.com/identity/protocols/OpenIDConnect#getcredentials)
for information on how to obtain them.

The redirect URI of the SATOSA proxy must be registered with Google. The
redirect URI to register with Google is the same as specified as the first
redirect URI in `config["client"]["client_metadata"]["redirect_uris"]`.
It should use the available variables, `<base_url>` and `<name>`, where:

1. `<base_url>` is the base url of the proxy as specified in the `BASE` configuration parameter
in `proxy_conf.yaml`, e.g. "https://proxy.example.com".
1. `<name>` is the plugin name specified in the `name` configuration parameter defined in the plugin configuration file.

The example config in `google_backend.yaml.example`:

```yaml
name: google
config:
  client:
    client_metadata:
      redirect_uris: [<base_url>/<name>]
[...]
```
together with `BASE: "https://proxy.example.com"` in `proxy_conf.yaml` would
yield the redirect URI `https://proxy.example.com/google` to register with Google.

A list of all claims possibly released by Google can be found [here](https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo),
which should be used when configuring the attribute mapping (see above).


#### Facebook
The default configuration file can be
found [here](../example/plugins/backends/facebook_backend.yaml.example).

The only parameters necessary to configure is the credentials,
the "App ID" (`client_id`) and "App Secret" (`client_secret`), issued by Facebook.
See the [registration instructions](https://developers.facebook.com/docs/apps/register)
for information on how to obtain them.

A list of all user attributes released by Facebook can be found [here](https://developers.facebook.com/docs/graph-api/reference/v2.5/user),
which should be used when configuring the attribute mapping (see above).

### Ping frontend for simple heartbeat monitoring

The ping frontend responds to a query with a simple
200 OK and is intended to be used as a simple heartbeat monitor, 
for example by a load balancer. The default configuration file can
be found [here](../example/plugins/frontends/ping_frontend.yaml.example).

### Micro services

Additional behaviour can be configured in the proxy through so called *micro services*. There are two different types
of micro services: *request micro services* which are applied to the incoming request, and *response micro services*
which are applied to the incoming response from the target provider.

The following micro services are bundled with SATOSA.

#### Adding static attributes to all responses

To add a set of static attributes, use the `AddStaticAttributes` class which will add
pre-configured (static) attributes, see the
[example configuration](../example/plugins/microservices/static_attributes.yaml.example).

The static attributes are described as key-value pairs in the YAML file, e.g:

```
organisation: Example Org.
country: Sweden
```

where the keys are the internal attribute names defined in `internal_attributes.yaml`.

#### Filtering attribute values

Attribute values delivered from the target provider can be filtered based on a per target provider per requester basis
using the `FilterAttributeValues` class. See the [example configuration](../example/plugins/microservices/filter_attributes.yaml.example).

The filters are described as regular expressions in a YAML file with the following structure:

```yaml
<target_provider>:
    <requester>:
        <attribute_name>: <regex_filter>
```

where the empty string (`""`) can be used as a key on any level to describe a default filter.
The filters are applied such that all attribute values matched by the regular expression are preserved, while any
non-matching attribute values will be discarded.

##### Examples
Filter attributes from the target provider `https://provider.example.com`, to only preserve values starting with the
string `"foo:bar"`:
```yaml
"https://provider.example.com":
    "":
        "": "^foo:bar"
```

Filter the attribute `attr1` to only preserve values ending with the string `"foo:bar"`:
```yaml
"":
    "":
        "attr1": "foo:bar$"
```

Filter the attribute `attr1` to the requester `https://provider.example.com`, to only preserver values containing
the string `"foo:bar"`:
```yaml
"":
    "https://client.example.com":
        "attr1": "foo:bar"
```

#### Route to a specific backend based on the requester
To choose which backend (essentially choosing target provider) to use based on the requester, use the
`DecideBackendByRequester` class which implements that special routing behavior. See the
[example configuration](../example/plugins/microservices/requester_based_routing.yaml.example).

#### Filter authentication requests to target SAML entities
If using the `SAMLMirrorFrontend` module and some of the target providers should support some additional SP's, the
`DecideIfRequesterIsAllowed` micro service can be used. It provides a rules mechanism to describe which SP's are
allowed to send requests to which IdP's. See the [example configuration](../example/plugins/microservices/allowed_requesters.yaml.example).

Metadata containing all SP's (any SP that might be allowed by a target IdP) must be in the metadata configured in the
`SAMLMirrorFrontend` plugin config.

The rules are described using `allow` and `deny` directives under the `rules` configuration parameter.

In the following example, the target IdP `target_entity_id1` only allows requests from `requester1` and `requester2`.
```yaml
rules:
    target_entity_id1:
        allow: ["requester1", "requester2"]
```

SP's are by default denied if the IdP has any rules associated with it (i.e, the IdP's entity id is a key in the `rules` mapping).
However, if the IdP does not have any rules associated with its entity id, all SP's are by default allowed.

Deny all but one SP:
```yaml
rules:
    target_entity_id1:
        allow: ["requester1"]
        deny: ["*"]
```

Allow all but one SP:
```yaml
rules:
    target_entity_id1:
        allow: ["*"]
        deny: ["requester1"]
```

#### Account linking

To allow account linking (multiple accounts at possibly different target providers are linked together as belonging to
the same user), an external service can be used. See the [example config](../example/plugins/microservices/account_linking.yaml.example)
which is intended to work with the [ALService](https://github.com/its-dirg/ALservice) (or any other service providing
the same REST API).

This micro service must be the first in the list of configured micro services in the `proxy_conf.yaml` to ensure
correct functionality.

#### User consent management

To handle user consent of released information, an external service can be used. See the [example config](../example/plugins/microservices/consent.yaml.example)
which is intended to work with the [CMService](https://github.com/its-dirg/CMservice) (or any other service providing
the same REST API).

This micro service must be the last in the list of configured micro services in the `proxy_conf.yaml` to ensure
correct functionality.

#### LDAP attribute store

An identifier such as eduPersonPrincipalName asserted by an IdP can be used to look up a person record
in an LDAP directory to find attributes to assert about the authenticated user to the SP. The identifier
to consume from the IdP, the LDAP directory details, and the mapping of attributes found in the
directory may all be confingured on a per-SP basis. The input to use when hashing to create a
persistent NameID may also be obtained from attributes returned from the LDAP directory. To use the
LDAP microservice install the extra necessary dependencies with `pip install satosa[ldap]` and then see the
[example config](../example/plugins/microservices/ldap_attribute_store.yaml.example).

### Custom plugins

It's possible to write custom plugins which can be loaded by SATOSA. They have to be contained in a Python module,
which must be importable from the one of the paths specified by `CUSTOM_PLUGIN_MODULE_PATHS` in `proxy_conf.yaml`.

Depending on which type of plugin it is, it has to inherit from the correct base class and implement the specified
methods:
* Frontends must inherit `satosa.frontends.base.FrontendModule`.
* Backends must inherit `satosa.backends.base.BackendModule`.
* Request micro services must inherit `satosa.micro_services.base.RequestMicroService`.
* Request micro services must inherit `satosa.micro_services.base.ResponseMicroService`.

# <a name="saml_metadata" style="color:#000000">Generate proxy metadata</a>

The proxy metadata is generated based on the front-/backend plugins listed in `proxy_conf.yaml`
using the `satosa-saml-metadata` (installed globally by SATOSA installation).

To produce signed SAML metadata for all SAML front- and backend modules, run the following command:

```bash
satosa-saml-metadata <path to proxy_conf.yaml> <path to key for signing> <path to cert for signing>
```

Detailed usage instructions can be viewed by running `satosa-saml-metadata --help`.

# Running the proxy application

The SATOSA proxy is a Python WSGI application and so may be run using any WSGI compliant web server.

## Using Gunicorn

Gunicorn 'Green Unicorn' is a Python WSGI HTTP Server for UNIX and is the server used most often
to run the proxy. In a production deployment the Gunicorn server is often proxied by a
full featured general purpose web server (in a reverse proxy architecture) such as Nginx or 
Apache HTTP Server to help buffer slow clients and enable more sophisticated error page rendering.

Start the proxy server with the following command:
```bash
gunicorn -b<socket address> satosa.wsgi:app --keyfile=<https key> --certfile=<https cert>
```
where
* `socket address` is the socket address that `gunicorn` should bind to for incoming requests, e.g. `0.0.0.0:8080`
* `https key` is the path to the private key to use for HTTPS, e.g. `pki/key.pem`
* `https cert` is the path to the certificate to use for HTTPS, e.g. `pki/cert.pem`

This will use the `proxy_conf.yaml` file in the working directory. If the `proxy_conf.yaml` is
located somewhere else, use the environment variable `SATOSA_CONFIG` to specify the path, e.g.:

```bash
set SATOSA_CONFIG=/home/user/proxy_conf.yaml
```

## Using Apache HTTP Server and mod\_wsgi

See the [auxiliary documentation for running using mod\_wsgi](mod_wsgi.md).


