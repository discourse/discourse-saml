# frozen_string_literal: true

require "rails_helper"

describe "SAML POST-mode functionality", type: :request do
  before do
    SiteSetting.saml_enabled = true
    OmniAuth.config.test_mode = false
    SiteSetting.saml_target_url = "https://example.com/samlidp"
  end

  it "does not affect functionality when disabled" do
    SiteSetting.saml_request_method = "GET"
    post "/auth/saml"
    expect(response.status).to eq(302)
    expect(response.location).to start_with("https://example.com/samlidp")
  end

  it "serves an auto-submitting POST form when enabled" do
    SiteSetting.saml_request_method = "POST"
    post "/auth/saml"
    expect(response.status).to eq(200)
    expect(response.headers["content-type"]).to eq("text/html")
    expect(response.body).to have_tag(
      "form",
      with: {
        "action" => "https://example.com/samlidp",
        "method" => "post",
      },
    )

    expect(response.body).to have_tag(
      "form input",
      with: {
        "name" => "SAMLRequest",
        "type" => "hidden",
      },
    )

    html = Nokogiri.HTML5(response.body)
    script_url = html.at("script").attribute("src").value
    script_nonce = html.at("script").attribute("nonce").value

    csp = response.headers["content-security-policy"]

    script_src =
      csp.split(";").find { |directive| directive.strip.start_with?("script-src") }.split(" ")

    included_in_csp =
      script_src.any? do |allowed_src|
        script_url.start_with?(allowed_src) || ("'nonce-#{script_nonce}'" == allowed_src)
      end

    expect(included_in_csp).to eq(true)
  end

  it "embeds keys when enabled and authn requests signed" do
    SiteSetting.saml_request_method = "POST"
    SiteSetting.saml_authn_requests_signed = true

    SiteSetting.saml_sp_private_key = <<~SAML_KEY
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
SAML_KEY
    SiteSetting.saml_sp_certificate = <<~SAML_CERT
-----BEGIN CERTIFICATE-----
MIIFHTCCAwWgAwIBAgIUApYH9HGz/B2ieNzqlDJLZjxWTUcwDQYJKoZIhvcNAQEN
BQAwGjEYMBYGA1UEAwwPY2FzLmV4YW1wbGUub3JnMB4XDTI0MTAxMjA0NDIxNloX
DTQ0MTAxMjA0NDIxNlowGjEYMBYGA1UEAwwPY2FzLmV4YW1wbGUub3JnMIICIjAN
BgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvb3BKjzQhrxPC3Ti1EgtnLFzf6kF
SIaOOjIQWf7MHtir7AwyCcBaFhfQKU5NG4XUva2CEeYf+k1zw1AaPoISDwxZ/aJG
CO7bfrKQ3kd5//wjiXr6/92qLHy1yH72eJQ7+bkkCgNGlJEwxyyCkoOd02KGp0Ui
ci+piGy6g8GPwd63xIjZMNahym53oFE+ikzAa33L3dTbZ8JR11Aw93OxyMomvDYF
1ofJhe/UvvtlupMRKGHMAAWliY5cN8TN7ityaqHBUx01Exj6BYGnT5sUhLdrhAhE
iMUi+y+1T01a62lCuteDMbj3ef+TeOYxavMLF7P0zz5v6tJOOegTtr8+S86gd7b9
ktrZsPpB68S6JYM7G124q3zHj0m/u9/RuF9eMN0TtwCSuFaKiS97x6e43Eec+Noi
xe/mRCKGxRNMeNjPk1hPExvcaMTAq83VLUkXMG1z2xe4rnpCNe02TUg2x3D1NvQI
vndCXCmnU2CBl9Aaox/2VS7ioGQDglZWNatfQVRo8WCfz7+vj+PZo66PYthMxIiI
HDbPTSLRdp6PNVKbRkg0PPheGJAWC6pjIsi3lwTX8qS2naiogVndqMR8UcbS1w02
urmY589boBS9Asa4tA7Uf27EROqYJ0TfzWwjMI/OLY0T9KfXp6ba2l5U2dBX5s+t
w9zdV9thEwFOYzsCAwEAAaNbMFkwHQYDVR0OBBYEFEnDAnxTrXH0o6TbVFZ9s1mB
QEpKMDgGA1UdEQQxMC+CD2Nhcy5leGFtcGxlLm9yZ4YcY2FzLmV4YW1wbGUub3Jn
L2lkcC9tZXRhZGF0YTANBgkqhkiG9w0BAQ0FAAOCAgEAVPRYITQAPfcmmoVjE3Rd
NDjlWXRwwlLOYg2bkoVUATuSUoH17AxOmVQYjN40ZbGYrvJyj2QFh4QkdOCfAcf2
6Jv4r38cQ6CarfrppK9mRZnCipzSqz0mA6/7slyVjcFMdhxYzfKZESYapXJsQqzZ
z25lk5Vw2SPmSKdvu6uEIxVhFtgGInHpSI399uOsh4bPwody06brJY5hkfVbs2Kb
rU3i2ePdP13DIQBhjvEeeeyGu6eMvR/q4z5AH9dlWqfQmDcHojh7RTnnCXemGBYE
He3S5Vtcbg6b13D53epwxHybbsyE3GRFAEu7b50aVWMai98TmvhjxOoZ+mUM8G1X
TMMCDSt1PTL29igMn+vI/unR78TcbaFBLHaWm6B3eTQ9kzHkD0ghb4xwQmaaiFob
cC+o3lYMsH+e2ELOlSPuWsAx3+vCFuA7NE0bpo7cq8GPvR7tRoF4ymVao6cAM6g+
AfD4utLuU29hRArX/g3fVgXUyi5e0rFgFEtKgL9FoaL12MnDri7Y14TnfW33Tb66
aT1p8VgZgSjpeokzhBdl/cB9Uu5XBMUjP4VkHTfvTFLUnjAM0tSG0zFR1+dhAanz
KvkG7EGA2ZZPsnTXQe6q93qQa6H/P+kPtySWoivP8Ag3PP5SMgfVMLrYNdTwVeje
d/tLr9JXjnmxxvqoAAZ+zHA=
-----END CERTIFICATE-----
SAML_CERT
    post "/auth/saml"
    expect(response.status).to eq(200)
    expect(response.headers["content-type"]).to eq("text/html")

    html = Nokogiri.HTML5(response.body)
    expect(Base64.decode64(html.at("input").attribute("value").value)).to include("ds:Signature")
  end

  it "works for subfolder" do
    set_subfolder "/forum"
    SiteSetting.saml_request_method = "POST"

    post "/auth/saml"
    expect(response.status).to eq(200)
    expect(response.body).to have_tag(
      "form",
      with: {
        "action" => "https://example.com/samlidp",
        "method" => "post",
      },
    )

    expect(response.body).to have_tag(
      "form input",
      with: {
        "name" => "SAMLRequest",
        "type" => "hidden",
      },
    )

    html = Nokogiri.HTML5(response.body)
    script_url = html.at("script").attribute("src").value
    script_nonce = html.at("script").attribute("nonce").value

    csp = response.headers["content-security-policy"]
    script_src =
      csp.split(";").find { |directive| directive.strip.start_with?("script-src") }.split(" ")
    included_in_csp =
      script_src.any? do |allowed_src|
        script_url.start_with?(allowed_src) || ("'nonce-#{script_nonce}'" == allowed_src)
      end

    expect(included_in_csp).to eq(true)
  end
end
