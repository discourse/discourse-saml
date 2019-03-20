# name: discourse-saml
# about: SAML Auth Provider
# version: 0.1
# author: Robin Ward
# url: https://github.com/discourse/discourse-saml

register_asset 'stylesheets/saml.scss'

require_dependency 'auth/oauth2_authenticator'

gem 'macaddr', '1.0.0'
gem 'uuid', '2.3.7'
gem 'ruby-saml', '1.7.2'
gem "omniauth-saml", '1.9.0'

require_relative("lib/saml_authenticator")

after_initialize do
  [
    '../app/jobs/onceoff/migrate_saml_user_infos.rb'
  ].each { |path| load File.expand_path(path, __FILE__) }

  if GlobalSetting.try(:saml_slo_target_url).present?
    SiteSetting.class_eval do
      def self.logout_redirect
        Discourse.base_url + "/auth/saml/spslo"
      end
    end
  end

  if GlobalSetting.try(:saml_forced_domains).present?

    GlobalSetting.class_eval do

      def self.is_saml_forced_domain?(email)
        return if email.blank?

        GlobalSetting.saml_forced_domains.split(",").each do |domain|
          return true if email.end_with?("@#{domain}")
        end

        false
      end
    end

    UsersController.class_eval do
      alias_method :discourse_email_login, :email_login

      def email_login
        raise Discourse::NotFound if !SiteSetting.enable_local_logins_via_email
        return redirect_to path("/") if current_user

        expires_now
        params.require(:login)

        user = User.human_users.find_by_username_or_email(params[:login])
        user_presence = user.present? && !user.staged

        if user_presence && GlobalSetting.is_saml_forced_domain?(user.email)
          render_json_error(I18n.t("login.use_saml_auth"))
          return
        end

        discourse_email_login
      end
    end

    SessionController.class_eval do
      alias_method :discourse_create, :create

      def create
        params.require(:login)
        login = params[:login].strip
        login = login[1..-1] if login[0] == "@"
        user = User.find_by_username_or_email(login)

        if user && GlobalSetting.is_saml_forced_domain?(user.email)
          render json: { error: I18n.t("login.use_saml_auth") }
          return
        end

        discourse_create
      end
    end

    Users::OmniauthCallbacksController.class_eval do
      before_action :check_email_domain, only: [:complete]

      def check_email_domain
        auth = request.env["omniauth.auth"]
        raise Discourse::NotFound unless request.env["omniauth.auth"]

        auth[:session] = session

        return if params[:provider] == "saml"

        authenticator = self.class.find_authenticator(params[:provider])
        provider = DiscoursePluginRegistry.auth_providers.find { |p| p.name == params[:provider] }

        if authenticator.can_connect_existing_user? && current_user
          @auth_result = authenticator.after_authenticate(auth, existing_account: current_user)
        else
          @auth_result = authenticator.after_authenticate(auth)
        end

        email = @auth_result.user&.email || @auth_result.email

        if GlobalSetting.is_saml_forced_domain?(email)
          @auth_result.failed = true
          @auth_result.failed_reason = I18n.t("login.use_saml_auth")
          return
        end
      end

      alias_method :discourses_complete, :complete

      def complete
        if @auth_result&.failed?
          flash[:error] = @auth_result.failed_reason.html_safe
          return render('failure')
        end

        discourses_complete
      end
    end
  end
end

request_method = GlobalSetting.try(:saml_request_method) || 'get'

if request_method == 'post'
  after_initialize do

    module ::DiscourseSaml
      class Engine < ::Rails::Engine
        engine_name "discourse_saml"
        isolate_namespace DiscourseSaml
      end
    end

    class DiscourseSaml::DiscourseSamlController < ::ApplicationController
      skip_before_action :check_xhr
      skip_before_action :redirect_to_login_if_required, only: [:index]

      def index
        authn_request = OneLogin::RubySaml::Authrequest.new

        metadata_url = GlobalSetting.try(:saml_metadata_url)

        settings = nil

        if metadata_url
          idp_metadata_parser = OneLogin::RubySaml::IdpMetadataParser.new
          settings = idp_metadata_parser.parse_remote(metadata_url)
          settings.idp_sso_target_url = GlobalSetting.saml_target_url
          settings.idp_cert ||= GlobalSetting.try(:saml_cert)
        else
          settings = OneLogin::RubySaml::Settings.new(
            idp_sso_target_url: GlobalSetting.saml_target_url,
            idp_cert_fingerprint: GlobalSetting.try(:saml_cert_fingerprint),
            idp_cert_fingerprint_algorithm: GlobalSetting.try(:saml_cert_fingerprint_algorithm),
            idp_cert: GlobalSetting.try(:saml_cert),
          )
        end

        settings.compress_request = false
        settings.passive = false
        settings.issuer = Discourse.base_url
        settings.assertion_consumer_service_url = Discourse.base_url + "/auth/saml/callback"
        settings.name_identifier_format = GlobalSetting.try(:saml_name_identifier_format) || "urn:oasis:names:tc:SAML:2.0:protocol"

        saml_params = authn_request.create_params(settings, {})
        @saml_req = saml_params['SAMLRequest']

        script_path = '/plugins/discourse-saml/javascripts/submit-form-on-load.js'

        render inline: <<-HTML_FORM
  <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
    <body>
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
      <script src="#{UrlHelper.absolute(script_path, GlobalSetting.cdn_url)}"></script>
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
button_title = GlobalSetting.try(:saml_button_title) || GlobalSetting.try(:saml_title) || "with SAML"

auth_provider title: button_title,
              authenticator: SamlAuthenticator.new('saml'),
              message: "Authorizing with #{title} (make sure pop up blockers are not enabled)",
              frame_width: GlobalSetting.try(:saml_frame_width) || 600,
              frame_height: GlobalSetting.try(:saml_frame_height) || 400,
              full_screen_login: GlobalSetting.try(:saml_full_screen_login) || false,
              custom_url: request_method == 'post' ? "/discourse_saml" : nil
