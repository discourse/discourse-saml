# frozen_string_literal: true

require "rails_helper"

describe "SAML Single Log Out" do
  let(:user) { Fabricate(:user) }
  before { SiteSetting.saml_enabled = true }

  it "does nothing when SLO is not configured" do
    sign_in(user)
    delete "/session/#{user.username}", xhr: true
    expect(response.status).to eq(200)
    expect(response.parsed_body["redirect_url"]).to eq("/")
  end

  it "redirects to the omniauth route when SLO is configured" do
    SiteSetting.saml_slo_target_url = "https://example.com/slo-target"

    sign_in(user)
    delete "/session/#{user.username}", xhr: true
    expect(response.status).to eq(200)
    expect(response.parsed_body["redirect_url"]).to eq("/auth/saml/spslo")
  end
end
