> ⚠ Discourse has successfully integrated with SAML for many enterprises, but SAML integration is often complex, error prone, and typically requires customization / changes for that organization's _specific implementation_ of SAML. This work is best undertaken by software developers familiar with Discourse. We are highly familiar with Discourse, and available to do that work [on an enterprise hosting plan](https://discourse.org/buy).

### discourse-saml

A Discourse Plugin to enable authentication via SAML

Setting up your idp:
The entity-id should be: `http://example.com` or can be defined with `DISCOURSE_SAML_ISSUER`.
The consumer assertion service url should be: `https://example.com/auth/saml/callback` or can be defined with `DISCOURSE_SAML_ASSERTION_URL`.

You may need to set your idp to send an extra custom attribute 'screenName', that will become the users id.

For idp-initated SSO, use the following URL:
`https://example.com/auth/saml/callback`

### Configuration

For Docker based installations:

Add the following settings to your `app.yml` file in the Environment Settings section:

```
## Saml plugin setting
  DISCOURSE_SAML_TARGET_URL: https://idpvendor.com/saml/login/
  DISCOURSE_SAML_CERT_FINGERPRINT: "43:BB:DA:FF..."
  #DISCOURSE_SAML_REQUEST_METHOD: post
  #DISCOURSE_SAML_FULL_SCREEN_LOGIN: true
  DISCOURSE_SAML_CERT: "-----BEGIN CERTIFICATE-----
  ...
  -----END CERTIFICATE-----"
```

The `DISCOURSE_FULL_SCREEN_LOGIN` option allows the SSO login page to be presented within the main browser window, rather than a popup. If SAML is your only authentication method this can look neater, as when the user clicks the Log In button the login page will follow through within the main browser window rather than opening a pop-up. This setting is commented out by default - if you want full screen login uncomment that line and set the value to true (as per the example above).

For non docker:

Add the following settings to your `discourse.conf` file:

- `saml_target_url`

### Supported settings

- `DISCOURSE_SAML_SP_CERTIFICATE`: SAML Service Provider Certificate
- `DISCOURSE_SAML_SP_PRIVATE_KEY`: SAML Service Provider Private Key
- `DISCOURSE_SAML_ASSERTION_URL`: Callback URL  defaults to "base_url + /auth/saml/callback"
- `DISCOURSE_SAML_ISSUER`: SAML Service Provider entity-id (issuer)
- `DISCOURSE_SAML_AUTHN_REQUESTS_SIGNED`: defaults to false
- `DISCOURSE_SAML_WANT_ASSERTIONS_SIGNED`: defaults to false
- `DISCOURSE_SAML_NAME_IDENTIFIER_FORMAT`: defaults to "urn:oasis:names:tc:SAML:2.0:protocol"
- `DISCOURSE_SAML_DEFAULT_EMAILS_VALID`: defaults to true
- `DISCOURSE_SAML_VALIDATE_EMAIL_FIELDS`: defaults to blank. This setting accepts pipe separated group names that are supplied in `memberOf` attribute in SAML payload. If the group name specified in the value matches that from `memberOf` attribute than the `email_valid` is set to `true`, otherwise it defaults to `false`. This setting overrides `DISCOURSE_SAML_DEFAULT_EMAILS_VALID`.

If SAML provider return user informations  in "extrafields", use these settings:

- `DISCOURSE_SAML_EXTRAFIELD_EMAIL`: optional, defaults to blank: define user email  
- `DISCOURSE_SAML_EXTRAFIELD_FIRSTNAME`: optional, define user firstname
- `DISCOURSE_SAML_EXTRAFIELD_LASTNAME`: optional, define user lastname

"FIRSTNAME" & "LASTNAME" will be use for fullname, if only one of them are set, fullname will be firstname || lastname

- `DISCOURSE_SAML_EXTRAFIELD_COMPANY`: optional, add user company in fullname : fullname + (company)  


### Converting an RSA Key to a PEM

If the idp has an RSA key split up as modulus and exponent, this javascript library makes
it easy to convert to pem:

https://www.npmjs.com/package/rsa-pem-from-mod-exp

### License

MIT

