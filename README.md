### discourse-saml

A Discourse Plugin to enable authentication via SAML

Setting up your idp:
The entity-id should be: http://example.com
The consumer assertion service url should be: https://example.com/auth/saml/callback

You may need to set your idp to send an extra custom attribute 'screenName', that will become the users id.

For idp-initated SSO, use the following URL:
https://example.com/auth/saml/callback

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
- `DISCOURSE_SAML_AUTHN_REQUESTS_SIGNED`: defaults to false
- `DISCOURSE_SAML_WANT_ASSERTIONS_SIGNED`: defaults to false
- `DISCOURSE_SAML_NAME_IDENTIFIER_FORMAT`: defaults to "urn:oasis:names:tc:SAML:2.0:protocol"
- `DISCOURSE_SAML_DEFAULT_EMAILS_VALID`: defaults to true
- `DISCOURSE_SAML_VALIDATE_EMAIL_FIELDS`: defaults to blank. This setting accepts pipe separated group names that are supplied in `memberOf` attribute in SAML payload. If the group name specified in the value matches that from `memberOf` attribute than the `email_valid` is set to `true`, otherwise it defaults to `false`. This setting overrides `DISCOURSE_SAML_DEFAULT_EMAILS_VALID`.

### Convering an RSA Key to a PEM

If the idp has an RSA key split up as modulus and exponent, this javascript library makes
it easy to convert to pem:

https://www.npmjs.com/package/rsa-pem-from-mod-exp

### License

MIT

