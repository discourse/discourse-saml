# frozen_string_literal: true
require "rails_helper"

describe "SAML staged user handling", type: :request do
  let(:staged) { Fabricate(:staged) }

  before do
    SiteSetting.saml_enabled = true
    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:saml] = OmniAuth::AuthHash.new(
      provider: "saml",
      uid: "123545",
      info: OmniAuth::AuthHash::InfoHash.new(nickname: staged.username, email: staged.email),
    )

    UsersController.any_instance.stubs(:honeypot_value).returns(nil)
    UsersController.any_instance.stubs(:challenge_value).returns(nil)
  end

  it "works" do
    get "/auth/saml/callback"

    expect(response.status).to eq(302)
    expect(response.location).to eq("http://test.localhost/")
    expect(server_session[:authentication] || session[:authentication]).to include(
      username: staged.username,
      email: staged.email,
    )
    expect(JSON.parse(cookies[:authentication_data])["username"]).to eq(staged.username)

    post "/u.json", params: { name: staged.name, username: staged.username, email: staged.email }
    expect(response.status).to eq(200)

    expect(UserAssociatedAccount.where(user: staged).count).to eq(1)
    expect(staged.reload.staged).to eq(false)

    expect(session[:current_user_id]).to eq(staged.id)
  end
end
