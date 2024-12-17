# frozen_string_literal: true

require "rails_helper"

describe ::DiscourseSaml::SamlReplayCache do
  let(:redis) { Discourse.redis }
  let(:now) { Time.utc(2024, 11, 16, 7, 25, 0) }

  def create_saml_response(
    assertion_id: "abc123",
    not_on_or_after: now + 1.hour,
    session_not_on_or_after: now + 2.hours
  )
    response_xml = <<~XML
    <?xml version="1.0"?>
    <samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
                    ID="_response123"
                    IssueInstant="#{now.iso8601}">
      <saml:Assertion ID="#{assertion_id}"
                      IssueInstant="#{now.iso8601}">
        <saml:Issuer>https://idp.cat.com</saml:Issuer>
        <ds:Signature>
          <ds:SignedInfo>
            <ds:Reference URI="##{assertion_id}"/>
          </ds:SignedInfo>
        </ds:Signature>
        <saml:Conditions NotOnOrAfter="#{not_on_or_after.iso8601}"/>
        <saml:AuthnStatement AuthnInstant="#{now.iso8601}"
                             SessionNotOnOrAfter="#{session_not_on_or_after.iso8601}"/>
      </saml:Assertion>
    </samlp:Response>
  XML

    OneLogin::RubySaml::Response.new(Base64.encode64(response_xml))
  end

  before do
    freeze_time now
    redis.del("#{described_class::CACHE_KEY_PREFIX}abc123")
  end

  it "accepts first use of an assertion" do
    response = create_saml_response
    expect(described_class.valid?(response)).to eq(true)
  end

  it "rejects repeated use of an assertion" do
    response = create_saml_response
    expect(described_class.valid?(response)).to eq(true)
    expect(described_class.valid?(response)).to eq(false)
  end

  it "uses earliest expiry from conditions or session" do
    early_expiry = now + 30.minutes
    late_expiry = now + 2.hours

    response =
      create_saml_response(not_on_or_after: early_expiry, session_not_on_or_after: late_expiry)

    expect(described_class.valid?(response)).to eq(true)
    expect(redis.ttl("#{described_class::CACHE_KEY_PREFIX}abc123")).to be_within(1).of(
      30.minutes.to_i,
    )
  end

  it "rejects expired assertions" do
    response = create_saml_response(not_on_or_after: now - 1.minute)
    expect(described_class.valid?(response)).to eq(false)
  end
end
