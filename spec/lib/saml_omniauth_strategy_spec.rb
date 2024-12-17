# frozen_string_literal: true

describe ::DiscourseSaml::SamlOmniauthStrategy do
  let(:strategy) { described_class.new(->(env) { [200, env, "app"] }) }
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

    Base64.encode64(response_xml)
  end

  before do
    freeze_time now

    OmniAuth.config.test_mode = true
    env = Rack::MockRequest.env_for("/auth/saml/callback")
    env["rack.session"] = {}
    strategy.call!(env)
  end

  context "when handling SAML responses" do
    it "rejects replayed assertions" do
      allow(strategy).to receive(:fail!)
      strategy.request.params["SAMLResponse"] = create_saml_response
      strategy.request.params["SameSite"] = "1"

      strategy.callback_phase

      strategy.callback_phase

      expect(strategy).to have_received(:fail!).with(:saml_assertion_replay_detected)
    end

    # defensive testing but indicates that new assertion IDs are accepted
    it "accepts new assertions" do
      allow(strategy).to receive(:fail!)
      strategy.request.params["SAMLResponse"] = create_saml_response(assertion_id: "derp")
      strategy.request.params["SameSite"] = "1"
      strategy.callback_phase

      strategy.request.params["SAMLResponse"] = create_saml_response(assertion_id: "burp")
      strategy.callback_phase

      expect(strategy).not_to have_received(:fail!).with(:saml_assertion_replay_detected)
    end
  end
end
