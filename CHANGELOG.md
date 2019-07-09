# Changelog

## 4.1.0 (2019-07-09)

Trigger new version build to automatically upload to PyPI and docker hub.

- Add release instructions


## 4.0.0 (2019-07-09)

- Remove the warning filter; users must set the filter themselves
- Refactor internal data representation
  - Deprecate satosa.internal_data module
  - Use satosa.internal module
  - Store the NameID value as satosa.internal.InternalData.subject_id
  - Store the NameID nameid-format as satosa.internal.InternalData.subject_type
- Deprecate hash configuration option set in internal attributes
- Deprecate USER_ID_HASH_SALT configuration option
- Remove attribute hashing
- Deprecate UserIdHasher classes
- Deprecate UserIdHashType enum
- Support SAML NameID nameid-format emailAddress and unspecified
- Accept authn response with no NameID element
- Reset state after cookie decryption failure
- Add API to load data in Context object
  - KEY_BACKEND_METADATA_STORE
  - KEY_TARGET_ENTITYID
  - KEY_FORCE_AUTHN
  - KEY_MEMORIZED_IDP
- Add initial eIDAS support
- Support memoization of IdP selection when using MDQ
- plugins: Warn when AssertionConsumerService binding is HTTP-Redirect in the saml2 backend
- plugins: Add SAMLUnsolicitedFrontend frontend
- plugins: Add SAMLVirtualCoFrontend frontend
- plugins: Add extra_scopes configuration to support multiple scopes
- plugins: Use the latest pyop version
- plugins: Add primary identifier micro-service
- plugins: Misc fixes and improvents for LDAP attribute store micro-service
- plugins: Add verify_ssl option to OIDC backend
- plugins: Add hasher micro-service
- plugins: Add support in frontend for common domain cookie
- plugins: Add Ping frontend
- plugins: Fixes for the account linking micro-service
- tests: Misc improvements
- tests: Use latest pytest
- build: Set supported python versions to py35 py36 py37 and pypy3
  - Dropped support for py34
- build: Set minimum supported pysaml2 version
- docs: Instructions to use with Apache and mod_wsgi
- docs: Add satosa-users mailing list information
- docs: Add ui_info in example configs
- docs: Add GÉANT contribution notice
- docs: Misc typos and improvements
