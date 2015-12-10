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
     configuration" section of the [proxy configuration instructions](README.md)
     for more information.
     To specify the necessary plugins make sure to include the following
     configuration parameter values:
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

1. Configure the plugins
  1. Rename `plugins/saml2_frontend.yaml.example` to `plugins/saml2_frontend.yaml`
     and `plugins/openid_backend.yaml.example` to `plugins/openid_backend.yaml`
     ```bash
     mv plugins/saml2_frontend.yaml.example plugins/saml2_frontend.yaml
     mv plugins/openid_backend.yaml.example plugins/openid_backend.yaml
     ```

  1. Specify the necessary configuration parameters, see the "Plugins" section
     of the [proxy configuration instructions](README.md) for more information.

1. Generate the SAML metadata, see the "SAML metadata" section of the
   [proxy configuration instructions](README.md) for more information.
   ```bash
   make_saml_metadata.py proxy_conf.yaml
   ```

1. Run the proxy application
   ```bash
   gunicorn -b<socket address> --keyfile <HTTPS key> --certfile <HTTPS cert> satosa.proxy_server:app
   ```
