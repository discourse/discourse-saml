# name: discourse-saml
# about: SAML Auth Provider
# version: 0.1
# author: Robin Ward

require_dependency 'auth/oauth2_authenticator'

gem 'macaddr', '1.0.0'
gem 'uuid', '2.3.7'
gem 'ruby-saml', '1.0.0'
gem "omniauth-saml", '1.4.1'

request_method = GlobalSetting.try(:saml_request_method) || 'get'

class SamlAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :saml,
                      :name => 'saml',
                      :issuer => 'discourse',
                      :idp_sso_target_url => GlobalSetting.saml_target_url,
                      :idp_cert_fingerprint => GlobalSetting.try(:saml_cert_fingerprint),
                      :custom_url => (GlobalSetting.try(:saml_request_method) == 'post') ? "/discourse_saml" : nil
  end

  def after_authenticate(auth)
    result = Auth::Result.new

    uid = auth[:uid]
    result.username = uid
    result.email = uid
    result.email_valid = true

    current_info = ::PluginStore.get("saml", "saml_user_#{uid}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    end

    result.user ||= User.where(email: result.email).first

    result.extra_data = { saml_user_id: uid }
    result
  end

  def after_create_account(user, auth)
    ::PluginStore.set("saml", "saml_user_#{auth[:extra_data][:saml_user_id]}", {user_id: user.id })
  end
end

if request_method == 'post'
  after_initialize do

    module ::DiscourseSaml
      class Engine < ::Rails::Engine
        engine_name "discourse_saml"
        isolate_namespace DiscourseSaml
      end
    end

    class DiscourseSaml::DiscourseSamlController < ::ApplicationController
      skip_before_filter :check_xhr
      def index
        authn_request = OneLogin::RubySaml::Authrequest.new
        settings = OneLogin::RubySaml::Settings.new(:idp_sso_target_url => GlobalSetting.saml_target_url,
                                                    :idp_cert_fingerprint => GlobalSetting.try(:saml_cert_fingerprint))

        saml_params = authn_request.create_params(settings, {})
        @saml_req = saml_params['SAMLRequest']

        render text: <<-HTML_FORM
  <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
    <body onload="document.forms[0].submit()">
      <noscript>
        <p>
          <strong>Note:</strong> Since your browser does not support JavaScript,
          you must press the Continue button once to proceed.
        </p>
      </noscript>
      <form action="#{GlobalSetting.saml_target_url}" method="post">
        <div>
          <input type="hidden" name="SAMLRequest" value="#{@saml_req}"/>
        </div>
        <noscript>
          <div>
            <input type="submit" value="Continue"/>
          </div>
        </noscript>
      </form>
    </body>
  </html>
HTML_FORM
      end
    end

    DiscourseSaml::Engine.routes.draw do
      get '/' => 'discourse_saml#index'
    end

    Discourse::Application.routes.append do
      mount ::DiscourseSaml::Engine, at: "/discourse_saml"
    end
  end
end

title = GlobalSetting.try(:saml_title) || "SAML"
button_title = GlobalSetting.try(:saml_title) || "with SAML"

auth_provider :title => button_title,
              :authenticator => SamlAuthenticator.new('saml'),
              :message => "Authorizing with #{title} (make sure pop up blockers are not enabled)",
              :frame_width => 600,
              :frame_height => 380,
              :background_color => '#003366',
              :custom_url => request_method == 'post' ? "/discourse_saml" : nil
