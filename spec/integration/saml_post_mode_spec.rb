# frozen_string_literal: true

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

    # Generate a temporary key for signing
    key = OpenSSL::PKey::RSA.new 2048
    name = OpenSSL::X509::Name.parse "CN=nobody/DC=example"
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 0
    cert.not_before = Time.now
    cert.not_after = Time.now + 3600
    cert.public_key = key.public_key
    cert.subject = name
    cert.sign key, OpenSSL::Digest.new("SHA1")

    SiteSetting.saml_sp_private_key = key.to_pem
    SiteSetting.saml_sp_certificate = cert.to_pem
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
