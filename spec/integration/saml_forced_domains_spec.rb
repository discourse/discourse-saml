# frozen_string_literal: true

require 'rails_helper'

describe "SAML Forced Domains" do
  let(:password) { "abcdefghijklmnop" }
  let(:saml_user) do
    Fabricate(
      :user,
      email: "user@samlonly.example.com",
      password: password
    ).tap { |u| u.activate }
  end
  let(:other_user) do
    Fabricate(
      :user,
      email: "user@example.com",
      password: password
    ).tap { |u| u.activate }
  end

  before { OmniAuth.config.test_mode = true }

  describe "username/password login" do
    it "works as normal when feature disabled" do
      post "/session.json", params: {
        login: saml_user.username, password: password
      }
      expect(response.status).to eq(200)
      expect(session[:current_user_id]).to eq(saml_user.id)
    end

    it "blocks logins for blocked domains" do
      global_setting :saml_forced_domains, "samlonly.example.com"
      post "/session.json", params: {
        login: saml_user.username, password: password
      }
      expect(response.status).to eq(200)
      expect(response.parsed_body["error"]).to eq(I18n.t("login.use_saml_auth"))
      expect(session[:current_user_id]).to eq(nil)
    end

    it "allows logins for other domains" do
      post "/session.json", params: {
        login: other_user.username, password: password
      }
      expect(response.status).to eq(200)
      expect(session[:current_user_id]).to eq(other_user.id)
    end
  end

  describe "email login" do
    it "works as normal when feature disabled" do
      post "/u/email-login.json", params: { login: saml_user.email }
      expect(response.status).to eq(200)
      expect_job_enqueued(job: :critical_user_email, args: {
        user_id: saml_user.id, type: 'email_login'
      })
    end

    it "blocks login for blocked domains" do
      global_setting :saml_forced_domains, "samlonly.example.com"
      post "/u/email-login.json", params: { login: saml_user.email }
      expect(response.status).to eq(403)
      expect_not_enqueued_with(job: :critical_user_email)
    end

    it "allows login for other domains" do
      global_setting :saml_forced_domains, "samlonly.example.com"
      post "/u/email-login.json", params: { login: other_user.email }
      expect(response.status).to eq(200)
      expect_job_enqueued(job: :critical_user_email, args: {
        user_id: other_user.id, type: 'email_login'
      })
    end
  end

  describe "external login" do
    let(:mock_auth) do
      OmniAuth::AuthHash.new(
        provider: 'google_oauth2',
        uid: '123545',
        info: OmniAuth::AuthHash::InfoHash.new(
          email: saml_user.email,
        ),
        extra: { raw_info: { email_verified: true } }
      )
    end

    before do
      SiteSetting.enable_google_oauth2_logins = true
      OmniAuth.config.mock_auth[:google_oauth2] = mock_auth
      OmniAuth.config.mock_auth[:saml] = mock_auth
    end

    it "works as normal when feature disabled" do
      get "/auth/google_oauth2/callback"
      expect(response.status).to eq(302)
      expect(session[:current_user_id]).to eq(saml_user.id)
    end

    it "blocks login for blocked domains" do
      global_setting :saml_forced_domains, "samlonly.example.com"
      get "/auth/google_oauth2/callback"
      expect(response.status).to eq(200)
      expect(response.body).to include(I18n.t("login.use_saml_auth"))
      expect(session[:current_user_id]).to eq(nil)
    end

    it "allows SAML login for blocked domains" do
      global_setting :saml_forced_domains, "samlonly.example.com"
      get "/auth/saml/callback"
      expect(response.status).to eq(302)
      expect(session[:current_user_id]).to eq(saml_user.id)
    end

    it "allows login for other domains" do
      global_setting :saml_forced_domains, "samlonly.example.com"
      mock_auth.info.email = other_user.email
      get "/auth/google_oauth2/callback"
      expect(response.status).to eq(302)
      expect(session[:current_user_id]).to eq(other_user.id)
    end
  end
end
