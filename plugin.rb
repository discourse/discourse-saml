# frozen_string_literal: true

# name: discourse-saml
# about: SAML Auth Provider
# version: 0.1
# author: Robin Ward
# url: https://github.com/discourse/discourse-saml

require_dependency 'auth/oauth2_authenticator'

gem 'macaddr', '1.0.0'
gem 'uuid', '2.3.7'
gem 'rexml', '3.2.5'
gem 'ruby-saml', '1.13.0'
gem "omniauth-saml", '1.9.0'

require_relative "lib/saml_authenticator"

on(:before_session_destroy) do |data|
  next if !GlobalSetting.try(:saml_slo_target_url).present?
  data[:redirect_url] = Discourse.base_path + "/auth/saml/spslo"
end

module ::DiscourseSaml
  def self.is_saml_forced_domain?(email)
    return if !GlobalSetting.try(:saml_forced_domains).present?
    return if email.blank?

    GlobalSetting.saml_forced_domains.split(",").each do |domain|
      return true if email.end_with?("@#{domain}")
    end

    false
  end
end

after_initialize do
  # "SAML Forced Domains" - Prevent login via email
  on(:before_email_login) do |user|
    if ::DiscourseSaml.is_saml_forced_domain?(user.email)
      raise Discourse::InvalidAccess.new(nil, nil, custom_message: "login.use_saml_auth")
    end
  end

  # "SAML Forced Domains" - Prevent login via regular username/password
  module ::DiscourseSaml::SessionControllerExtensions
    def login_error_check(user)
      if ::DiscourseSaml.is_saml_forced_domain?(user.email)
        return { error: I18n.t("login.use_saml_auth") }
      end
      super
    end
  end
  ::SessionController.prepend(::DiscourseSaml::SessionControllerExtensions)

  # "SAML Forced Dvomains" - Prevent login via other omniauth strategies
  class ::DiscourseSaml::ForcedSamlError < StandardError; end
  on(:after_auth) do |authenticator, result|
    next if authenticator.name == "saml"
    if [result.user&.email, result.email].any? { |e| ::DiscourseSaml.is_saml_forced_domain?(e) }
      raise ::DiscourseSaml::ForcedSamlError
    end
  end
  Users::OmniauthCallbacksController.rescue_from(::DiscourseSaml::ForcedSamlError) do
    flash[:error] = I18n.t("login.use_saml_auth")
    render('failure')
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
          settings.idp_sso_target_url ||= GlobalSetting.saml_target_url
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
        settings.issuer = SamlAuthenticator.saml_base_url
        settings.assertion_consumer_service_url = SamlAuthenticator.saml_base_url + "/auth/saml/callback"
        settings.name_identifier_format = GlobalSetting.try(:saml_name_identifier_format) || "urn:oasis:names:tc:SAML:2.0:protocol"

        saml_params = authn_request.create_params(settings, {})
        @saml_req = saml_params['SAMLRequest']

        script_path = '/plugins/discourse-saml/javascripts/submit-form-on-load.js'

        html = <<~HTML
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
        HTML

        render html: html.html_safe
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

pretty_name = GlobalSetting.try(:saml_title) || "SAML"
button_title = GlobalSetting.try(:saml_button_title) || GlobalSetting.try(:saml_title) || "with SAML"

auth_provider title: button_title,
              pretty_name: pretty_name,
              authenticator: SamlAuthenticator.new('saml'),
              custom_url: request_method == 'post' ? "/discourse_saml" : nil
