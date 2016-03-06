# Proxy: OpenID Connect <-> SAML2
After following the [installation instructions](README.md#installation), the proxy must
be configured with a OpenID Connect frontend and a SAML2 backend.

## Configuration

1. Copy the necessary base configurations from the `<satosa_path>/example` directory:
   ```bash
   mkdir -p oidc-saml2/plugins
   cp example/{proxy_conf.yaml.example,internal_attributes.yaml.example} oidc-saml2/
   cp example/plugins/frontends/oidc_frontend.yaml.example oidc-saml2/plugins/
   cp example/plugins/backends/saml2_backend.yaml.example oidc-saml2/plugins/
   ```

1. Configure the proxy:
  1. Rename `proxy_conf.yaml.example` to `proxy_conf.yaml`:
     ```bash
     mv proxy_conf.yaml.example proxy_conf.yaml
     ```

  1. Edit the necessary proxy configuration parameters, see the [SATOSA proxy
     configuration](README.md#proxy_conf) section of the proxy configuration instructions
     for more information.
     To specify the necessary plugins make sure to include the following
     configuration parameter values:
     ```yaml  
     PLUGIN_PATH:
       - plugins
     BACKEND_MODULES:
       - "saml2_backend"
     FRONTEND_MODULES:
       - "oidc_frontend"
     ```

1. Configure the attribute mapping:
  1. Rename `internal_attributes.yaml.example` to `internal_attributes.yaml`:
     ```bash
     mv internal_attributes.yaml.example internal_attributes.yaml
     ```

  1. Map the necessary attributes, see the [Attribute mapping configuration](README.md#attr_map)
     section of the proxy configuration instructions for more
     information.

1. Configure the plugins
  1. Rename `plugins/oidc_frontend.yaml.example` to `plugins/oidc_frontend.yaml`
     and `plugins/saml2_backend.yaml.example` to `plugins/saml2_backend.yaml`
     ```bash
     mv plugins/oidc_frontend.yaml.example plugins/oidc_frontend.yaml
     mv plugins/saml2_backend.yaml.example plugins/saml2_backend.yaml
     ```

  1. Specify the necessary configuration parameters, see the [Plugins](README.md#plugins) section
     of the proxy configuration instructions for more information.

1. Generate the SAML metadata, see the [SAML metadata](README.md#saml_metadata) section of the
   proxy configuration instructions for more information. Note: SAML metadata can only be generated
   for the backend, so make sure to specify the option `-b`. 

1. Start the proxy application, see the [Running the proxy application](README.md#run) section of
   the proxy configuration instructions for more information.
