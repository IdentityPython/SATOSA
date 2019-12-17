# Changelog

## 6.0.0 (2019-12-17)

- properly support mutliple values when converting internal attributes to OIDC
  claims. For all claims other than the ones define in OIDC core specification,
  the same values as the ones that have been set in the internal representation
  will be returned.
- improve log handling
- micro-services: Better handling of single-value attribute by LdapAttributeStore


## 5.0.0 (2019-11-07)

*Notice*: Support for python 3.5 has been dropped.

- Add a dict-like interface to the internal objects
- Fix escaped chars in RegEx strings
- tests: fix warnings
- build: drop support for python 3.5
- misc: typos and formatting


## 4.5.0 (2019-11-05)

- add options in saml-frontend to encrypt assertion from AuthnResponse
- use saml2.extension.mdui in place of saml2.extension.ui
- improve log handling
- remove logging around state-cookie loading
- print the absolute path of the configuration when failing to read it
- error out if no backend or frontend is configured
- frontends: oidc: support extra_scopes
- frontends: SAMLVirtualCoFrontend: add attribute scope
- backends: orcid: add state parameter to authorization request
- backends: orcid: fix read address attribute
- backends: orcid: fix authorization token header
- backends: bitbucket: new oauth2 backend
- backends: facebook: add more configuration options
- micro-services: improve the ldap_attribute_store
- build: refactor the start.sh docker script
- build: improve travis stages for new releases
- docs: add sequence diagrams for SAML-to-SAML flow
- docs: improve configuration docs
- docs: improve micro-service docs
- misc: correct typos


## 4.4.0 (2019-07-09)

Trigger new version build to automatically upload to PyPI,
docker hub and GitHub.

- Fix travis CI/CD configuration


## 4.3.0 (2019-07-09)

Trigger new version build to automatically upload to PyPI and docker hub.

- Fix travis CI/CD configuration


## 4.2.0 (2019-07-09)

Trigger new version build to automatically upload to PyPI and docker hub.

- Fix travis CI/CD configuration
- Fix typo in release instructions


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
