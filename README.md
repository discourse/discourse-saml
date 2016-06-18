### discourse-saml

A Discourse Plugin to enable authentication via SAML

Setting up your idp:
The entitiy-id should be: http://example.com
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
  DISCOURSE_SAML_CERT: "-----BEGIN CERTIFICATE----- 
  ...
  -----END CERTIFICATE-----"
```

For non docker:

Add the following settings to your `discourse.conf` file:

- `saml_target_url`

### Convering an RSA Key to a PEM

If the idp has an RSA key split up as modulus and exponent, this javascript library makes
it easy to convert to pem:

https://www.npmjs.com/package/rsa-pem-from-mod-exp

### License

MIT

