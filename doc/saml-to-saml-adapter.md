# Proxy: SAML2 <--> SAML2

There might be a mismatch between the SAML profile of an IDP (1:1) or a federation (1:many) 
and an SP with a limited SAML implementation. The proxy can convert the SAMl profile 
to make both sides compatible. 

## Support for a NameID format Emailaddress

If the SP requires a NameID format emailAddress add this configuration entry the SAMLFrontend 
file:

module: satosa.frontends.saml2.SAMLFrontend
name: Saml2IDP
config:
  idp_config:
    ...
    service:
      idp:
        ...
        name_id_format: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

## Renaming friendly attribute names
 
 If an SP uses friendly attribute names instead of conforming to the X.500/LDAP Attribute Profile, 
 the proxy can rename the friendly names. In the meantime attributes can be renamed using the internal_attributes configuration. 
 For example, to rename a backend attribute called "principalName" to "surname" at the
 frontend, set different attribute_profile values for the backend and frontend:
 
    attributes:
      ...
      surname:
        facebook: [last_name]
        linkedin: [lastName]
        openid: [family_name]
        saml: [sn, surname]
        saml_backend: [principalName]

The additional profile 'saml_backend' needs to be registered with the backend configuration:

    module: satosa.backends.saml2.SAMLBackend
    name: Saml2
    config:
      attribute_profile: saml_backend
      sp_config:
         ...