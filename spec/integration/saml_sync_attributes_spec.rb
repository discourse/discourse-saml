# frozen_string_literal: true

describe "SAML Overrides Email", type: :request do
  fab!(:initial_email) { "initial@example.com" }
  fab!(:initial_username) { "initialusername" }
  fab!(:new_email) { "new@example.com" }
  fab!(:new_username) { "newusername" }
  fab!(:user) { Fabricate(:user, email: initial_email, username: initial_username) }
  fab!(:uac) do
    UserAssociatedAccount.create!(user: user, provider_name: "saml", provider_uid: "12345")
  end

  before do
    SiteSetting.saml_enabled = true

    OmniAuth.config.test_mode = true
    OmniAuth.config.mock_auth[:saml] = OmniAuth::AuthHash.new(
      provider: "saml",
      uid: "12345",
      info: OmniAuth::AuthHash::InfoHash.new(email: new_email, nickname: new_username),
    )
  end

  it "doesn't sync attributes by default" do
    get "/auth/saml/callback"
    expect(response.status).to eq(302)
    expect(session[:current_user_id]).to eq(user.id)

    user.reload
    expect(user.email).to eq(initial_email)
    expect(user.username).to eq(initial_username)
  end

  it "updates user email if enabled" do
    SiteSetting.saml_sync_email = true

    get "/auth/saml/callback"
    expect(response.status).to eq(302)
    expect(session[:current_user_id]).to eq(user.id)

    user.reload
    expect(user.username).to eq(initial_username)
  end

  it "updates username if enabled" do
    SiteSetting.saml_omit_username = true

    get "/auth/saml/callback"
    expect(response.status).to eq(302)
    expect(session[:current_user_id]).to eq(user.id)

    user.reload
    expect(user.username).to eq(new_username)
  end
end
