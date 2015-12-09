# Proxy: SAML2 <-> OpenID Connect
After following the [installation instructions](README.md), the proxy must
be configured with a SAML2 frontend and an OpenID Connect backend.

## Configuration

1. Copy the necessary base configurations from the `<satosa_path>/example` directory:
   ```bash
   mkdir -p saml2-oidc/plugins
   cp <satosa_path>/example/{proxy_server.py,proxy_conf.yaml.example,internal_attributes.yaml.example} saml2-oidc/ # proxy application and its config
   cp <satosa_path>/example/plugins/frontends/saml2_frontend.yaml.example saml2-oidc/plugins/
   cp <satosa_path>/example/plugins/backends/openid_backend.yaml.example saml2-oidc/plugins/
   ```

1. Configure the proxy:
  1. Rename `proxy_conf.yaml.example` to `proxy_conf.yaml`:
     ```bash
     mv proxy_conf.yaml.example proxy_conf.yaml
     ```

  1. Edit the necessary proxy configuration parameters, see the "SATOSA proxy
     configuration" section of the [proxy configuration instructions](README.md).
     ```yaml  
     PLUGIN_PATH:
       - plugins
     BACKEND_MODULES:
       - openid_backend
     FRONTEND_MODULES:
       - saml2_frontend
     ```
1. Configure the attribute mapping:
  1. Rename `internal_attributes.yaml.example` to `internal_attributes.yaml`:
     ```bash
     mv internal_attributes.yaml.example internal_attributes.yaml
     ```

  1. Map the necessary attributes, see the "Attribute mapping configuration"
     section of the [proxy configuration instructions](README.md) for more
     information.


## Using Google as the backing OpenID Connect Provider
When using Google as the identity provider some additional configuration is necessary, so the backend configuration in [`google_backend.yaml.example`](../example/plugins/backends/google_backend.yaml.example)
should be used instead of `openid_backend.yaml.example`.

The only parameters necessary to configure is the credentials,
the `client_id` and `client_secret`, issued by Google. See [OAuth 2.0 credentials](https://developers.google.com/identity/protocols/OpenIDConnect#getcredentials) for information on how to obtain them.

The `redirect_uri` of the SATOSA proxy must be registered with Google. The
redirect URI to register with Google is "<base_url>/google", where `<base_url>`
is the base url of the proxy as specified in the `BASE` configuration parameter
in `proxy_conf.yaml`, e.g. "https://proxy.example.com/google".

A list of all claims possibly released by Google can be found [here](https://developers.google.com/identity/protocols/OpenIDConnect#obtainuserinfo),
which should be used when configuring the attribute mapping (see above).
