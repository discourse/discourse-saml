# frozen_string_literal: true

# name: discourse-saml
# about: SAML Auth Provider
# version: 1.0
# author: Discourse Team
# url: https://github.com/discourse/discourse-saml

gem "macaddr", "1.0.0"
gem "uuid", "2.3.7"
gem "ruby-saml", "1.17.0"

if OmniAuth.const_defined?(:AuthenticityTokenProtection) # OmniAuth 2.0
  gem "omniauth-saml", "2.2.1"
else
  gem "omniauth-saml", "1.10.5"
end

enabled_site_setting :saml_enabled if !GlobalSetting.try("saml_target_url")

on(:before_session_destroy) do |data|
  next if !DiscourseSaml.setting(:slo_target_url).present?
  data[:redirect_url] = Discourse.base_path + "/auth/saml/spslo"
end

module ::DiscourseSaml
  def self.enabled?
    # Legacy - we only check the enabled site setting
    # if the environment-variables are **not** present
    !!GlobalSetting.try("saml_target_url") || SiteSetting.saml_enabled
  end

  def self.setting(key, prefer_prefix: "saml_")
    if prefer_prefix == "saml_"
      SiteSetting.get("saml_#{key}")
    else
      GlobalSetting.try("#{prefer_prefix}#{key}") || SiteSetting.get("saml_#{key}")
    end
  end

  def self.is_saml_forced_domain?(email)
    return if !enabled?
    return if !DiscourseSaml.setting(:forced_domains).present?
    return if email.blank?

    DiscourseSaml
      .setting(:forced_domains)
      .split(/[,|]/)
      .each { |domain| return true if email.end_with?("@#{domain}") }

    false
  end
end

after_initialize do
  if !!GlobalSetting.try("saml_target_url")
    # Configured via environment variables. Hide all the site settings
    # from the UI to avoid confusion
    saml_site_setting_keys = []

    SiteSetting.defaults.all.keys.each do |k|
      next if !k.to_s.start_with?("saml_")
      saml_site_setting_keys << k
    end

    if SiteSetting.respond_to?(:hidden_settings_provider)
      register_modifier(:hidden_site_settings) { |hidden| hidden + saml_site_setting_keys }
    else
      SiteSetting.hidden_settings.concat(saml_site_setting_keys)
    end
  end

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

  # "SAML Forced Domains" - Prevent login via other omniauth strategies
  class ::DiscourseSaml::ForcedSamlError < StandardError
  end
  on(:after_auth) do |authenticator, result|
    next if authenticator.name == "saml"
    if [result.user&.email, result.email].any? { |e| ::DiscourseSaml.is_saml_forced_domain?(e) }
      raise ::DiscourseSaml::ForcedSamlError
    end
  end
  Users::OmniauthCallbacksController.rescue_from(::DiscourseSaml::ForcedSamlError) do
    flash[:error] = I18n.t("login.use_saml_auth")
    render("failure")
  end
end

require_relative "lib/discourse_saml/saml_omniauth_strategy"
require_relative "lib/discourse_saml/saml_replay_cache"
require_relative "lib/saml_authenticator"

# Allow GlobalSettings to override the translations
# If the global settings are not provided, will use the `js.login.saml.name` and `js.login.saml.title` translations
name = GlobalSetting.try(:saml_title)
button_title = GlobalSetting.try(:saml_button_title) || GlobalSetting.try(:saml_title)

auth_provider title: button_title, pretty_name: name, authenticator: SamlAuthenticator.new
