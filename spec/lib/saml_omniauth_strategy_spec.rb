# frozen_string_literal: true

describe ::DiscourseSaml::SamlOmniauthStrategy do
  let(:strategy) { described_class.new(->(env) { [200, env, "app"] }) }

  let(:settings_double) do
    instance_double(OneLogin::RubySaml::Settings, idp_cert_fingerprint: "AB:CD:EF:12:34:56")
  end
  let(:response_object) do
    instance_double(
      OneLogin::RubySaml::Response,
      assertion_id: "abc123",
      response_id: "123",
      name_id: "test@example.com",
      is_valid?: true,
      attributes: {
      },
      settings: settings_double,
      not_on_or_after: Time.current + 1.hour,
      session_expires_at: Time.current + 1.hour,
      sessionindex: {
      },
    ).tap { |response| allow(response).to receive(:soft=).and_return(response) }
  end

  before do
    allow(strategy).to receive(:fail!)
    allow(OneLogin::RubySaml::Response).to receive(:new).and_return(response_object)

    OmniAuth.config.test_mode = true
    env = Rack::MockRequest.env_for("/auth/saml/callback")
    env["rack.session"] = {}
    strategy.call!(env)
  end

  describe "#handle_response" do
    context "when replay protection is enabled" do
      before { SiteSetting.saml_replay_protection_enabled = true }

      it "fails when a replay is detected" do
        allow(DiscourseSaml::SamlReplayCache).to receive(:valid?).and_return(false)

        strategy.send(:handle_response, "raw_response", {}, settings_double) {}

        expect(strategy).to have_received(:fail!).with(:saml_assertion_replay_detected)
      end

      it "proceeds when no replay is detected" do
        allow(DiscourseSaml::SamlReplayCache).to receive(:valid?).and_return(true)

        expect {
          strategy.send(:handle_response, "raw_response", {}, settings_double) {}
        }.not_to raise_error

        expect(strategy).not_to have_received(:fail!)
      end
    end

    context "when replay protection is disabled" do
      before { SiteSetting.saml_replay_protection_enabled = false }

      it "does not check for replays" do
        allow(DiscourseSaml::SamlReplayCache).to receive(:valid?)
        expect(DiscourseSaml::SamlReplayCache).not_to have_received(:valid?)

        expect {
          strategy.send(:handle_response, "raw_response", {}, settings_double) {}
        }.not_to raise_error
      end
    end
  end
end
