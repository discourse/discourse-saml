# frozen_string_literal: true

require 'rails_helper'

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
      }
    )

    expect(response.body).to have_tag(
      "form input",
      with: {
        "name" => "SAMLRequest",
        "type" => "hidden",
      }
    )

    expect(response.body).to have_tag("script")
  end
end
