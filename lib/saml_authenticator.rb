# frozen_string_literal: true

class SamlAuthenticator < ::Auth::OAuth2Authenticator
  attr_reader :user, :attributes, :info

  def info=(info)
    @info = info.present? ? info.with_indifferent_access : info
  end

  def initialize(name, opts = {})
    opts[:trusted] ||= true
    super(name, opts)
  end

  def attribute_name_format(type = "basic")
    "urn:oasis:names:tc:SAML:2.0:attrname-format:#{type}"
  end

  def setting(key)
    # In almost all circumstances, `name` is `saml`.
    # However, some other plugins choose to re-use this Authenticator class
    # with a different `name`. This helper lets them have their own settings,
    # which automatically fall back to the `saml_` defaults.
    ::DiscourseSaml.setting(key, prefer_prefix: "#{name}_")
  end

  def request_attributes
    attrs = "email|name|first_name|last_name"
    custom_attrs = setting(:request_attributes)

    attrs = "#{attrs}|#{custom_attrs}" if custom_attrs.present?

    attrs.split("|").uniq.map do |name|
      { name: name, name_format: attribute_name_format, friendly_name: name }
    end
  end

  def attribute_statements
    result = {}
    statements = "name:fullName,name|email:email,mail|first_name:first_name,firstname,firstName|last_name:last_name,lastname,lastName|nickname:screenName"
    custom_statements = setting(:attribute_statements)

    statements = "#{statements}|#{custom_statements}" if custom_statements.present?

    statements.split("|").map do |statement|
      attrs = statement.split(":")
      next if attrs.count != 2
      (result[attrs[0]] ||= []) << attrs[1].split(",")
      result[attrs[0]].flatten!
    end

    result
  end

  def register_middleware(omniauth)
    omniauth.provider ::DiscourseSaml::SamlOmniauthStrategy,
                      name: name,
                      setup: lambda { |env|
                        setup_strategy(env["omniauth.strategy"])
                      }
  end

  def setup_strategy(strategy)
    strategy.options.deep_merge!(
      issuer: SamlAuthenticator.saml_base_url,
      idp_sso_target_url: setting(:target_url),
      idp_slo_target_url: setting(:slo_target_url).presence,
      slo_default_relay_state: SamlAuthenticator.saml_base_url,
      idp_cert_fingerprint: setting(:cert_fingerprint).presence,
      idp_cert_fingerprint_algorithm: setting(:cert_fingerprint_algorithm),
      idp_cert: setting(:cert).presence,
      idp_cert_multi: setting(:cert_multi).presence,
      request_attributes: request_attributes,
      attribute_statements: attribute_statements,
      assertion_consumer_service_url: SamlAuthenticator.saml_base_url + "/auth/#{name}/callback",
      single_logout_service_url: SamlAuthenticator.saml_base_url + "/auth/#{name}/slo",
      name_identifier_format: setting(:name_identifier_format).presence,
      request_method: (setting(:request_method)&.downcase == 'post') ? "POST" : "GET",
      certificate: setting(:sp_certificate).presence,
      private_key: setting(:sp_private_key).presence,
      security: {
        authn_requests_signed: !!setting(:authn_requests_signed),
        want_assertions_signed: !!setting(:want_assertions_signed),
        logout_requests_signed: !!setting(:logout_requests_signed),
        logout_responses_signed: !!setting(:logout_responses_signed),
        signature_method: XMLSecurity::Document::RSA_SHA1
      },
      idp_slo_session_destroy: proc { |env, session| @user.user_auth_tokens.destroy_all; @user.logged_out }
    )
  end

  def attr(key)
    info[key] || attributes[key]&.join(",") || ""
  end

  def after_authenticate(auth)
    self.info = auth[:info]

    extra_data = auth.extra || {}
    raw_info = extra_data[:raw_info]
    @attributes = raw_info&.attributes || {}

    auth[:uid] = attributes['uid'].try(:first) || auth[:uid] if setting(:use_attributes_uid)
    uid = auth[:uid]

    auth[:provider] = name
    auth[:info][:email] ||= uid

    result = super

    if setting(:log_auth)
      ::PluginStore.set("saml", "#{name}_last_auth", auth.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_raw_info", raw_info.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_extra", extra_data.inspect)
    end

    if setting(:debug_auth)
      data = {
        uid: uid,
        info: info,
        extra: extra_data
      }
      log("#{name}_auth: #{data.inspect}")
    end

    result.username = if uid && setting(:use_attributes_uid)
      uid
    else
      auth.info.nickname
    end

    result.name = begin
      fullname = auth.info[:name].presence # From fullName, name, or other custom attribute_statement
      fullname ||= "#{auth.info[:first_name]} #{auth.info[:last_name]}"
      fullname
    end

    if result.respond_to?(:skip_email_validation) && setting(:skip_email_validation)
      result.skip_email_validation = true
    end

    if setting(:validate_email_fields).present? && attributes['memberOf'].present?
      unless (setting(:validate_email_fields).split("|").map(&:downcase) & attributes['memberOf'].map(&:downcase)).empty?
        result.email_valid = true
      else
        result.email_valid = false
      end
    elsif !setting(:default_emails_valid).nil?
      result.email_valid = setting(:default_emails_valid)
    else
      result.email_valid = true
    end

    result.extra_data[:saml_attributes] = attributes
    result.extra_data[:saml_info] = info

    if result.user.blank?
      result.username = '' if setting(:clear_username)
      result.user = auto_create_account(result, uid) if setting(:auto_create_account) && result.email_valid
    else
      @user = result.user
      sync_groups
      sync_custom_fields
      sync_moderator
      sync_admin
      sync_trust_level
      sync_locale
    end

    result.overrides_username = setting(:omit_username)
    result.overrides_email = setting(:sync_email)

    result
  end

  def log(info)
    Rails.logger.warn("SAML Debugging: #{info}") if setting(:debug_auth)
  end

  def after_create_account(user, auth)
    super

    @user = user
    self.info = auth[:extra_data][:saml_info]
    @attributes = auth[:extra_data][:saml_attributes]

    sync_groups
    sync_moderator
    sync_admin
    sync_trust_level
    sync_custom_fields
    sync_locale
  end

  def auto_create_account(result, uid)
    try_email = result.email.presence
    return if User.find_by_email(try_email).present?

    # Use a mutex here to counter SAML responses that are sent at the same time and the same email payload
    DistributedMutex.synchronize("discourse_saml_#{try_email}") do
      try_name = result.name.presence
      try_username = result.username.presence

      user_params = {
        primary_email: UserEmail.new(email: try_email, primary: true),
        name: try_name || User.suggest_name(try_username || try_email),
        username: UserNameSuggester.suggest(try_username || try_name || try_email || uid),
        active: true
      }

      user = User.create!(user_params)
      after_create_account(user, result.as_json.with_indifferent_access)

      user
    end
  end

  def sync_groups
    return unless setting(:sync_groups).present?
    groups_fullsync = setting(:groups_fullsync) || false
    group_attribute = setting(:groups_attribute).presence || 'memberOf'
    user_group_list = (attributes[group_attribute] || []).map(&:downcase)

    if setting(:groups_ldap_leafcn).present?
      # Change cn=groupname,cn=groups,dc=example,dc=com to groupname
      user_group_list = user_group_list.map { |group| group.split(',').first.split('=').last }
    end

    if groups_fullsync
      user_has_groups = user.groups.where(automatic: false).pluck(:name).map(&:downcase)
      groups_to_add = user_group_list - user_has_groups
      if user_has_groups.present?
        groups_to_remove = user_has_groups - user_group_list
      end
    else
      total_group_list = (setting(:sync_groups_list) || "").split('|').map(&:downcase)
      groups_to_add = user_group_list + attr('groups_to_add').split(",").map(&:downcase)
      groups_to_remove = attr('groups_to_remove').split(",").map(&:downcase)

      if total_group_list.present?
        groups_to_add = total_group_list & groups_to_add

        removable_groups = groups_to_remove.dup
        groups_to_remove = total_group_list - groups_to_add
        groups_to_remove &= removable_groups if removable_groups.present?
      end
    end

    return if user_group_list.blank? && groups_to_add.blank? && groups_to_remove.blank?

    Group.where('LOWER(name) IN (?) AND NOT automatic', groups_to_add).each do |group|
      group.add user
    end

    Group.where('LOWER(name) IN (?) AND NOT automatic', groups_to_remove).each do |group|
      group.remove user
    end
  end

  def sync_custom_fields
    return if user.blank?

    request_attributes.each do |attr|
      key = attr[:name]
      user.custom_fields["#{name}_#{key}"] = attr(key) if attr(key).present?
    end

    sync_user_fields
    user.save_custom_fields
  end

  def sync_user_fields
    statements = setting(:user_field_statements) || ""

    statements.split("|").each do |statement|
      key, field_id = statement.split(":")
      next if key.blank? || field_id.blank?

      user.custom_fields["user_field_#{field_id}"] = attr(key) if attr(key).present?
    end
  end

  def sync_moderator
    return unless setting(:sync_moderator)

    is_moderator_attribute = setting(:moderator_attribute) || 'isModerator'
    is_moderator = ['1', 'true'].include?(attributes[is_moderator_attribute].try(:first).to_s.downcase)

    return if user.moderator == is_moderator

    user.moderator = is_moderator
    user.save
  end

  def sync_admin
    return unless setting(:sync_admin)

    is_admin_attribute = setting(:admin_attribute) || 'isAdmin'
    is_admin = ['1', 'true'].include?(attributes[is_admin_attribute].try(:first).to_s.downcase)

    return if user.admin == is_admin

    user.admin = is_admin
    user.save
  end

  def sync_trust_level
    return unless setting(:sync_trust_level)

    trust_level_attribute = setting(:trust_level_attribute) || 'trustLevel'
    level = attributes[trust_level_attribute].try(:first).to_i

    return unless level.between?(1, 4)

    if user.manual_locked_trust_level != level
      user.manual_locked_trust_level = level
      user.save
    end

    return if user.trust_level == level

    user.change_trust_level!(level, log_action_for: user)
  end

  def sync_locale
    return unless setting(:sync_locale)

    locale_attribute = setting(:locale_attribute) || 'locale'
    locale = attributes[locale_attribute].try(:first)

    return unless LocaleSiteSetting.valid_value?(locale)

    if user.locale != locale
      user.locale = locale
      user.save
    end
  end

  def enabled?
    # Checking target_url global setting for backwards compatibility
    # (the plugin used to be enabled-by-default)
    setting(:enabled) || !!GlobalSetting.try("#{name}_target_url")
  end

  def self.saml_base_url
    DiscourseSaml.setting(:base_url).presence || Discourse.base_url
  end

end
