# name: discourse-saml
# about: SAML Auth Provider
# version: 0.1
# author: Robin Ward

require_dependency 'auth/oauth2_authenticator'

gem 'macaddr', '1.0.0'
gem 'uuid', '2.3.7'
gem 'ruby-saml', '1.0.0'
gem "omniauth-saml", '1.4.1'

class SAMLAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :saml,
                      :name => 'saml',
                      :issuer => 'discourse',
                      :idp_sso_target_url => GlobalSetting.saml_target_url
  end

  def after_authenticate(auth)
    result = Auth::Result.new

    raise auth.inspect
    uid = auth[:uid]
    result.name = auth[:info].name
    result.username = uid
    result.email = auth[:info].email
    result.email_valid = true

    current_info = ::PluginStore.get("saml", "saml_user_#{uid}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    end
    result.extra_data = { saml_user_id: uid }
    result
  end

  def after_create_account(user, auth)
    ::PluginStore.set("saml", "saml_user_#{auth[:extra_data][:saml_user_id]}", {user_id: user.id })
  end

end

title = GlobalSetting.try(:saml_title) || "SAML"
button_title = GlobalSetting.try(:saml_title) || "with SAML"

auth_provider :title => button_title,
              :authenticator => SAMLAuthenticator.new('saml'),
              :message => "Authorizing with #{title} (make sure pop up blockers are not enabled)",
              :frame_width => 600,
              :frame_height => 380,
              :background_color => '#003366'
