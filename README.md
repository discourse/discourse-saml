### discourse-saml

A Discourse Plugin to enable authentication via SAML

### Configuration

Add the following settings to your Discourse `app.yml` file:


```
env:
  DISCOURSE_SAML_TARGET_URL: "value"
```
  
### Converting an RSA Key to a PEM

If the idp has an RSA key split up as modulus and exponent, this javascript library makes
it easy to convert to pem:

https://www.npmjs.com/package/rsa-pem-from-mod-exp

### License

MIT

