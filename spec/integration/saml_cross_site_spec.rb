# frozen_string_literal: true

require "rails_helper"

describe "SAML cross-site with same-site cookie", type: :request do
  let(:saml_response) do
    Base64.strict_encode64("<Response xmlns='urn:oasis:names:tc:SAML:2.0:protocol'/>")
  end

  before do
    OmniAuth.config.test_mode = false
    global_setting :saml_target_url, "https://example.com/samlidp"
  end

  it "serves an auto-submitting POST form" do
    post "/auth/saml/callback", params: { "SAMLResponse" => saml_response }
    expect(response.status).to eq(200)
    expect(response.body).to have_tag(
      "form",
      with: {
        "action" => "http://test.localhost/auth/saml/callback",
        "method" => "post",
      },
    )

    expect(response.body).to have_tag(
      "form input",
      with: {
        "name" => "SAMLResponse",
        "value" => saml_response,
        "type" => "hidden",
      },
    )

    expect(response.body).to have_tag(
      "form input",
      with: {
        "name" => "SameSite",
        "value" => "1",
        "type" => "hidden",
      },
    )

    expect(response.body).to have_tag("script")

    expect(response.has_header?("Set-Cookie")).to eq(false)
  end

  it "continues once the samesite form has been submitted" do
    post "/auth/saml/callback", params: { "SAMLResponse" => saml_response, "SameSite" => "1" }
    expect(response.status).to eq(302)
    expect(response.location).to eq("/auth/failure?message=invalid_ticket&strategy=saml")
  end
end
