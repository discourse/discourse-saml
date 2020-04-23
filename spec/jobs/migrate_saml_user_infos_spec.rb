# frozen_string_literal: true

require 'rails_helper'

RSpec.describe Jobs::MigrateSamlUserInfos do

  let(:user) { Fabricate(:user) }

  it "should copy user's saml id from `PluginStore` to `Oauth2UserInfo`" do
    uid = 7
    ::PluginStore.set("saml", "saml_user_#{uid}", user_id: user.id)

    described_class.new.execute_onceoff({})

    expect(Oauth2UserInfo.find_by(uid: uid, provider: "saml").user_id).to eq(user.id)

    described_class.new.execute_onceoff({}) # should not raise error if records already exist
  end

end
