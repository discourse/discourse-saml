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

require_relative "lib/discourse_saml/saml_omniauth_strategy"
require_relative "lib/saml_authenticator"

pretty_name = GlobalSetting.try(:saml_title) || "SAML"
button_title = GlobalSetting.try(:saml_button_title) || GlobalSetting.try(:saml_title) || "with SAML"

auth_provider title: button_title,
              pretty_name: pretty_name,
              authenticator: SamlAuthenticator.new('saml')
