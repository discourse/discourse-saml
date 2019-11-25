> ⚠ Discourse has successfully integrated with SAML for many enterprises, but SAML integration is often complex, error prone, and typically requires customization / changes for that organization's _specific implementation_ of SAML. This work is best undertaken by software developers familiar with Discourse. We are highly familiar with Discourse, and available to do that work [on an enterprise hosting plan](https://discourse.org/buy).

### About

A Discourse Plugin to enable authentication via SAML

Setting up your idp:
The entity-id should be: `http://example.com`
The consumer assertion service url should be: `https://example.com/auth/saml/callback`

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

### Group sync
- `DISCOURSE_SAML_SYNC_GROUPS`: Sync groups. Defaults to false.
- `DISCOURSE_SAML_GROUPS_ATTRIBUTE`: SAML attribute to use for group sync. Defaults to `memberOf`
- `DISCOURSE_SAML_GROUPS_FULLSYNC`: Should the assigned groups be completely synced including adding AND removing groups based on the IDP? Defaults to false. If set to true, `DISCOURSE_SAML_SYNC_GROUPS_LIST` and SAML attribute `groups_to_add`/`groups_to_remove` are not used.
- `DISCOURSE_SAML_SYNC_GROUPS_LIST`: Groups mentioned in this list are synced if they are referenced by the IDP (in `memberOf` SAML attribue). Any other groups will not be removed/updated.

### Other Supported settings

- `DISCOURSE_SAML_SP_CERTIFICATE`: SAML Service Provider Certificate
- `DISCOURSE_SAML_SP_PRIVATE_KEY`: SAML Service Provider Private Key
- `DISCOURSE_SAML_AUTHN_REQUESTS_SIGNED`: defaults to false
- `DISCOURSE_SAML_WANT_ASSERTIONS_SIGNED`: defaults to false
- `DISCOURSE_SAML_NAME_IDENTIFIER_FORMAT`: defaults to "urn:oasis:names:tc:SAML:2.0:protocol"
- `DISCOURSE_SAML_DEFAULT_EMAILS_VALID`: defaults to true
- `DISCOURSE_SAML_VALIDATE_EMAIL_FIELDS`: defaults to blank. This setting accepts pipe separated group names that are supplied in `memberOf` attribute in SAML payload. If the group name specified in the value matches that from `memberOf` attribute than the `email_valid` is set to `true`, otherwise it defaults to `false`. This setting overrides `DISCOURSE_SAML_DEFAULT_EMAILS_VALID`.
- `DISCOURSE_SAML_SYNC_MODERATOR`: defaults to false. If set to `true` user get moderator role if SAML attribute `isModerator` (or attribute specified by `DISCOURSE_SAML_MODERATOR_ATTRIBUTE`) is 1 or true.  
- `DISCOURSE_SAML_MODERATOR_ATTRIBUTE`: defaults to `isModerator`
- `DISCOURSE_SAML_SYNC_TRUST_LEVEL`: defaults to false. If set to `true` user's trust level is set to the SAML attribute `trustLevel` (or attribute specified by `DISCOURSE_SAML_TRUST_LEVEL_ATTRIBUTE`) which needs to be between 1 and 4.
- `DISCOURSE_SAML_TRUST_LEVEL_ATTRIBUTE`: defaults to `trustLevel`

### Converting an RSA Key to a PEM

If the idp has an RSA key split up as modulus and exponent, this javascript library makes it easy to convert to pem:

https://www.npmjs.com/package/rsa-pem-from-mod-exp

### License

MIT
