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
