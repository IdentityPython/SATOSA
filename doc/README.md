# SATOSA
This document describes how to install and configure the SATOSA proxy.


## Installation
1. Download the SATOSA proxy project as a [compressed archive ](https://github.com/its-dirg/SATOSA/releases)
   and unpack it to `<satosa_path>`.

1. Install the Python code and its requirements:

   ```bash  
   pip install `<satosa_path>` -r `<satosa_path>/requirements.txt`
   ```

## Configuration
All default configuration files, as well as an example WSGI application for the proxy, can be found
in the [example directory](../example).


### SATOSA proxy configuration: `proxy_conf.yaml.example`
| Parameter name | Data type | Example value | Description |
| -------------- | --------- | ------------- | ----------- |
| `BASE` | string | `https://proxy.example.com` | base url of the proxy |
| `SESSION_OPTS` | dict | `{session.type: memory, session.cookie_expires: Yes, session.auto: Yes}` | configuration options for [Beaker Session Middleware](http://beaker.readthedocs.org/en/latest/configuration.html)
| `COOKIE_STATE_NAME` | string | `vopaas_state` | name of cooke VOPaaS uses for preserving state between requests |
| `STATE_ENCRYPTION_KEY` | string | `52fddd3528a44157` | key used for encrypting the state cookie, will be overriden by the environment variable `SATOSA_STATE_ENCRYPTION_KEY` if it is set |
| `INTERNAL_ATTRIBUTES` | string | `example/internal_attributes.yaml` | path to attribute mapping
| `PLUGIN_PATH` | string[] | `[example/plugins/backends, example/plugins/frontends]` | list of directory paths containing any front-/backend plugins |
| `BACKEND_MODULES` | string[] | `[oidc_backend, saml2_backend]` | list of plugin names to load from the directories in `PLUGIN_PATH` |
| `FRONTEND_MODULES` | string[] | `[saml2_frontend]` | list of plugin names to load from the directories in `PLUGIN_PATH` |
| `USER_ID_HASH_SALT` | string | `61a89d2db0b9e1e2` | salt used when creating the persistent user identifier, will be overriden by the environment variable `SATOSA_USER_ID_HASH_SALT` if it is set |
| `CONSENT` | dict | see configuration of [Additional Services](#additional-services) | optional configuration of consent service |
| `ACCOUNT_LINKING` | dict | see configuration of [Additional Services](#additional-services) | optional configuration of account linking service |


#### Additional services
| Parameter name | Data type | Example value | Description |
| -------------- | --------- | ------------- | ----------- |
| `enable` | bool | `Yes` | whether the service should be used |
| `rest_uri` | string | `https://localhost` | url to the REST endpoint of the service |
| `redirect` | string | `https://localhost/redirect` | url to the endpoint where the user should be redirected for necessary interaction |
| `endpoint` | string | `handle_consent` | name of the endpoint in VOPaas where the response from the service is received |
| `sign_key`| string | `pki/consent.key` | path to key used for signing the requests to the service |
| `verify_ssl` | bool | `No` | whether the HTTPS certificate of the service should be verified when doing requests to it |

If using the [CMService](https://github.com/its-dirg/CMservice) for consent management and the [ALService](https://github.com/its-dirg/ALservice) for account linking, the `redirect` parameter should be `https://<host>/consent` and `https://<host>/approve` in the respective configuration entry.


### Attribute mapping configuration: `internal_attributes.yaml`

#### `attributes`
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
attribute to use, e.g. `address.formatted`.

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

This example defines two attributes internal to the proxy, named `mail` and `address` accessible to any plugins (e.g. front- and backends) in the proxy and their mapping
in two different "profiles", named `openid` and `saml` respectively.

The mapping between received attributes (proxy backend) <-> internal <-> returned attributes (proxy frontend) is defined as:

* Any plugin using the `openid` profile will use the attribute value from
  `email` delivered from the backing provider as the value for `mail`.
* Any plugin using the `saml` profile will use the attribute value from `mail`,
  `emailAdress` and `email` depending on which attributes are delivered by the
  backing provider as the value for `mail`.
* Any plugin using the `openid` profile will use the attribute value under the
  key `formatted` in the `address` attribute delivered by the backing provider.


#### `user_id_from_attr`
The user identifier generated by the backend module can be overridden by
specifying a list of internal attribute names under the `user_id_from_attr` key.
The attribute values of the attributes specified in this list will be
concatenated and hashed to be used as the user identifier.


#### `user_id_to_attr`
To store the user identifier in a specific internal attribute, the internal
attribute name can be specified in `user_id_to_attr`.
When the [ALService](https://github.com/its-dirg/ALservice) is used the
`user_id_to_attr` should be used, since that account linking service will
overwrite the user identifier generated by the proxy.


#### `hash`
The proxy can hash any attribute value (e.g., for obfuscation) before passing
it on to the client. The `hash` key should contain a list of all attribute names
for which the corresponding attribute value should be hashed before being
returned to the client.
