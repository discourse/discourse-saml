# frozen_string_literal: true

class SamlAuthenticator < ::Auth::ManagedAuthenticator
  def name
    "saml"
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

    attrs
      .split("|")
      .uniq
      .map { |name| { name: name, name_format: attribute_name_format, friendly_name: name } }
  end

  def attribute_statements
    result = {}
    statements =
      "name:fullName,name|email:email,mail|first_name:first_name,firstname,firstName|last_name:last_name,lastname,lastName|nickname:screenName"
    custom_statements = setting(:attribute_statements)

    statements = "#{statements}|#{custom_statements}" if custom_statements.present?

    statements
      .split("|")
      .map do |statement|
        attrs = statement.split(":", 2)
        next if attrs.count != 2
        (result[attrs[0]] ||= []) << attrs[1].split(",")
        result[attrs[0]].flatten!
      end

    result
  end

  def register_middleware(omniauth)
    omniauth.provider ::DiscourseSaml::SamlOmniauthStrategy,
                      name: name,
                      setup: lambda { |env| setup_strategy(env["omniauth.strategy"]) }
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
      idp_cert_multi: idp_cert_multi,
      request_attributes: request_attributes,
      attribute_statements: attribute_statements,
      assertion_consumer_service_url: SamlAuthenticator.saml_base_url + "/auth/#{name}/callback",
      single_logout_service_url: SamlAuthenticator.saml_base_url + "/auth/#{name}/slo",
      name_identifier_format: setting(:name_identifier_format).presence,
      request_method: (setting(:request_method)&.downcase == "post") ? "POST" : "GET",
      certificate: setting(:sp_certificate).presence,
      private_key: setting(:sp_private_key).presence,
      security: {
        authn_requests_signed: !!setting(:authn_requests_signed),
        want_assertions_signed: !!setting(:want_assertions_signed),
        logout_requests_signed: !!setting(:logout_requests_signed),
        logout_responses_signed: !!setting(:logout_responses_signed),
        metadata_signed: !!setting(:metadata_signed),
        signature_method: XMLSecurity::Document::RSA_SHA1,
      },
      idp_slo_session_destroy:
        proc do |env, session|
          user = CurrentUser.lookup_from_env(env)
          if user
            user.user_auth_tokens.destroy_all
            user.logged_out
          end
        end,
    )
  end

  def primary_email_verified?(auth_token)
    attributes = OneLogin::RubySaml::Attributes.new(auth_token.extra&.[](:raw_info) || {})

    group_attribute = setting(:groups_attribute)
    if setting(:validate_email_fields).present? && attributes.multi(group_attribute).present?
      validate_email_fields = setting(:validate_email_fields).split("|").map(&:downcase)
      member_of = attributes.multi(group_attribute).map { |g| g.downcase.split(",") }.flatten
      (validate_email_fields & member_of).present? ? true : false
    else
      setting(:default_emails_valid)
    end
  end

  def after_authenticate(auth)
    info = auth.info

    extra_data = auth.extra || {}
    attributes = extra_data[:raw_info] || OneLogin::RubySaml::Attributes.new

    auth[:uid] = attributes.single("uid") || auth[:uid] if setting(:use_attributes_uid)
    uid = auth[:uid]

    auth.info[:email] ||= uid if uid.to_s&.include?("@")

    auth.info[:nickname] = uid.to_s if uid && setting(:use_attributes_uid)

    auth.extra = { "raw_info" => attributes.attributes }
    result = super

    if setting(:log_auth)
      ::PluginStore.set("saml", "#{name}_last_auth", auth.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_raw_info", attributes.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_extra", extra_data.inspect)
    end

    if setting(:debug_auth)
      data = { uid: uid, info: info, attributes: attributes }
      log("#{name}_auth: #{data.inspect}")
    end

    result.skip_email_validation = true if setting(:skip_email_validation)

    if result.user.blank?
      result.username = "" if setting(:clear_username)
      result.user = auto_create_account(result, uid) if setting(:auto_create_account) &&
        result.email_valid
    else
      user = result.user
      sync_groups(user, attributes, info)
      sync_custom_fields(user, attributes, info)
      sync_moderator(user, attributes)
      sync_admin(user, attributes)
      sync_trust_level(user, attributes)
      sync_locale(user, attributes)
      Group.refresh_automatic_groups!(:admins, :moderators, :staff)
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

    uaa =
      UserAssociatedAccount.find_by(
        provider_name: auth.extra_data[:provider],
        provider_uid: auth.extra_data[:uid],
      )

    info = OmniAuth::AuthHash::InfoHash.new(uaa.info)
    attributes = OneLogin::RubySaml::Attributes.new(uaa.extra&.[]("raw_info") || {})

    sync_groups(user, attributes, info)
    sync_moderator(user, attributes)
    sync_admin(user, attributes)
    sync_trust_level(user, attributes)
    sync_custom_fields(user, attributes, info)
    sync_locale(user, attributes)
    Group.refresh_automatic_groups!(:admins, :moderators, :staff)
  end

  def auto_create_account(result, uid)
    try_email = result.email.presence
    return if User.find_by_email(try_email).present?

    # Use a mutex here to counter SAML responses that are sent at the same time and the same email payload
    DistributedMutex.synchronize("discourse_saml_#{try_email}") do
      user_params = {
        primary_email: UserEmail.new(email: try_email, primary: true),
        name: resolve_name(result.name, result.username, result.email),
        username: resolve_username(result.username, result.name, result.email, uid),
        active: true,
      }

      user = User.create!(user_params)

      session_data = result.session_data
      after_create_result = Auth::Result.from_session_data(session_data, user: user)

      after_create_account(user, after_create_result)

      user
    end
  end

  def sync_groups(user, attributes, info)
    return if setting(:sync_groups).blank?

    groups_fullsync = setting(:groups_fullsync)
    raw_group_list = attributes.multi(setting(:groups_attribute)) || []
    user_group_list = raw_group_list.map { |g| g.downcase.split(",") }.flatten

    if setting(:groups_ldap_leafcn).present?
      # Change cn=groupname,cn=groups,dc=example,dc=com to groupname
      user_group_list = user_group_list.map { |group| group.split("=", 2).last }
    end

    if groups_fullsync
      user_has_groups = user.groups.where(automatic: false).pluck(:name).map(&:downcase)
      groups_to_add = user_group_list - user_has_groups
      groups_to_remove = user_has_groups - user_group_list if user_has_groups.present?
    else
      total_group_list = setting(:sync_groups_list).split("|").map(&:downcase)

      groups_to_add = info["groups_to_add"] || attributes.multi("groups_to_add")&.join(",") || ""
      groups_to_add = groups_to_add.downcase.split(",")
      groups_to_add += user_group_list

      groups_to_remove =
        info["groups_to_remove"] || attributes.multi("groups_to_remove")&.join(",") || ""
      groups_to_remove = groups_to_remove.downcase.split(",")

      if total_group_list.present?
        groups_to_add = total_group_list & groups_to_add

        removable_groups = groups_to_remove.dup
        groups_to_remove = total_group_list - groups_to_add
        groups_to_remove &= removable_groups if removable_groups.present?
      end
    end

    return if user_group_list.blank? && groups_to_add.blank? && groups_to_remove.blank?

    Group
      .where("LOWER(name) IN (?) AND NOT automatic", groups_to_add)
      .each { |group| group.add user }

    Group
      .where("LOWER(name) IN (?) AND NOT automatic", groups_to_remove)
      .each { |group| group.remove user }
  end

  def sync_custom_fields(user, attributes, info)
    return if user.blank?

    request_attributes.each do |attr|
      key = attr[:name]
      val = info[key] || attributes.multi(key)&.join(",")
      user.custom_fields["#{name}_#{key}"] = val if val.present?
    end

    sync_user_fields(user, attributes, info)
    user.save_custom_fields
  end

  def sync_user_fields(user, attributes, info)
    statements = setting(:user_field_statements) || ""

    statements
      .split("|")
      .each do |statement|
        key, field_id = statement.split(":")
        next if key.blank? || field_id.blank?

        val = info[key] || attributes.multi(key)&.join(",")
        user.custom_fields["user_field_#{field_id}"] = val if val.present?
      end
  end

  def sync_moderator(user, attributes)
    return unless setting(:sync_moderator)

    is_moderator_attribute = setting(:moderator_attribute) || "isModerator"
    is_moderator = %w[1 true].include?(attributes.single(is_moderator_attribute).to_s.downcase)

    return if user.moderator == is_moderator

    user.moderator = is_moderator
    user.save
  end

  def sync_admin(user, attributes)
    return unless setting(:sync_admin)

    is_admin_attribute = setting(:admin_attribute) || "isAdmin"
    is_admin = %w[1 true].include?(attributes.single(is_admin_attribute).to_s.downcase)

    return if user.admin == is_admin

    user.admin = is_admin
    user.save
  end

  def sync_trust_level(user, attributes)
    return unless setting(:sync_trust_level)

    trust_level_attribute = setting(:trust_level_attribute) || "trustLevel"
    level = attributes.single(trust_level_attribute).to_i

    return unless level.between?(1, 4)

    if user.manual_locked_trust_level != level
      user.manual_locked_trust_level = level
      user.save
    end

    return if user.trust_level == level

    user.change_trust_level!(level, log_action_for: user)
  end

  def sync_locale(user, attributes)
    return unless setting(:sync_locale)

    locale_attribute = setting(:locale_attribute) || "locale"
    locale = attributes.single(locale_attribute)

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

  def can_connect_existing_user?
    false
  end

  def can_revoke?
    false
  end

  def self.saml_base_url
    DiscourseSaml.setting(:base_url).presence || Discourse.base_url
  end

  private

  def idp_cert_multi
    return if setting(:cert_multi).blank?

    certificates = setting(:cert_multi).split("|")
    certificates.push(setting(:cert)) if setting(:cert).present?

    { signing: certificates, encryption: [] }
  end

  def resolve_name(name, username, email)
    return name if name.present?

    suggester_input = username.presence
    suggester_input ||= email if SiteSetting.use_email_for_username_and_name_suggestions
    User.suggest_name(suggester_input)
  end

  def resolve_username(username, name, email, uid)
    suggester_input = [username, name]
    suggester_input << email if SiteSetting.use_email_for_username_and_name_suggestions
    suggester_input << uid

    UserNameSuggester.suggest(*suggester_input)
  end
end
