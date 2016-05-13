### discourse-saml

A Discourse Plugin to enable authentication via SAML

### Configuration

Add the following settings to your `discourse.conf` file:

- `saml_target_url`

### Convering an RSA Key to a PEM

If the idp has an RSA key split up as modulus and exponent, this javascript library makes
it easy to convert to pem:

https://www.npmjs.com/package/rsa-pem-from-mod-exp

### License

MIT

