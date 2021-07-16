# Changelog

## 7.0.3 (2021-01-21)

- dependencies: Set minimum pysaml2 version to v6.5.1 to fix internal XML
  parser issues around the xs and xsd namespace prefixes declarations


## 7.0.2 (2021-01-20) - Security release for pySAML2 dependency

- Add RegexSubProcessor attribute processor
- Fix SAMLVirtualCoFrontend metadata generation
- frontends: Deprecate the sign_alg and digest_alg configuration options on the
  saml2 frontend. Instead, use the signing_algorithm and digest_algorithm
  configuration options under the service/idp configuration path (not under
  service/idp/policy/default)
- backends: New backend to login with Apple ID
- dependencies: Set minimum pysaml2 version to v6.5.0 to make sure we get a
  version patched for CVE-2021-21238 and CVE-2021-21239
- build: Fix the CI base image
- tests: Fix entity-category checks
- docs: Document the sub_hash_salt configuration for the OIDC frontend
- examples: Add entityid_endpoint to the saml backend and frontend
  configuration
- examples: Fix the SAMLVirtualCoFrontend example configuration


## 7.0.1 (2020-06-09)

- build: fix the CI release process


## 7.0.0 (2020-06-09)

- Make the AuthnContextClassRefs available through the context
- Extend YAML parsing to understand the `!ENV` and `!ENVFILE` tags, that read
  values or file contents from the environment
- Add `satosa.yaml` module to handle YAML parsing
- BREAKING: Remove previously deprecated configuration options:
  - `hash`: use the hasher micro-service instead
  - `USER_ID_HASH_SALT`: use the hasher micro-service instead
- BREAKING: Remove previously deprecated classes:
  - `SAMLInternalResponse`: use `satosa.internal.InternalData` instead
  - `InternalRequest`: use `satosa.internal.InternalData` instead
  - `InternalResponse`: use `satosa.internal.InternalData` instead
  - `UserIdHashType`: use the hasher micro-service instead
  - `UserIdHasher`: use the hasher micro-service instead
- BREAKING: Remove previously deprecated functions:
  - `hash_attributes`: use the hasher micro-service instead
  - `oidc_subject_type_to_hash_type`: use `satosa.internal.InternalData.subject_type` directly
  - `saml_name_id_format_to_hash_type`: use `satosa.internal.InternalData.subject_type` directly
  - `hash_type_to_saml_name_id_format`: use `satosa.internal.InternalData.subject_type` directly
- BREAKING: Remove previously deprecated modules:
  - `src/satosa/internal_data.py`
- BREAKING: Remove previously deprecated properties of the `saml2.internal.InternalData` class:
  - `name_id`: use use `subject_id` instead,
  - `user_id`: use `subject_id` instead,
  - `user_id_hash_type`: use `subject_type` instead,
  - `approved_attributes`: use `attributes` instead,
- The cookie is now a session-cookie; To have the the cookie removed
  immediately after use, the CONTEXT_STATE_DELETE configuration option should
  be set to `True`
- Create dedicated module to handle the proxy version
- Set the logger to log to stdout on DEBUG level by default
- Cleanup code around the wsgi calls
- micro-services: separate core from micro-services; drop checks for
  micro-services order; drop references to the Consent and AccountLinking
  micro-services
- micro-services: generate a random name for the pool name when REUSABLE client
  strategy is used for the ldap-attribute-store micro-service.
- docs: improve example proxy configuration
- docs: minor fixes/typos/etc
- build: update CI to use Travis-CI stages
- build: run tests for Python3.8
- build: tag docker image by commit, branch, PR number, version and "latest"


## 6.1.0 (2020-02-28) - Security release for pySAML2 dependency

- Set the SameSite cookie attribute to "None"
- Add compatibility support for the SameSite attribute for incompatible
  browsers
- Set the Secure attribute of the cookie, always
- Set minimum pysaml2 version to make sure we get a version patched for
  CVE-2020-5390
- Fix typos and improve documetation
- Set the session-id when state is created
- Use LinkedIn API v2


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
