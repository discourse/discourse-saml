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
    GlobalSetting.try("#{name}_#{key}") || GlobalSetting.try("saml_#{key.to_s}")
  end

  def request_attributes
    attrs = "email|name|first_name|last_name"
    custom_attrs = GlobalSetting.try(:saml_request_attributes)

    attrs = "#{attrs}|#{custom_attrs}" if custom_attrs.present?

    attrs.split("|").uniq.map do |name|
      { name: name, name_format: attribute_name_format, friendly_name: name }
    end
  end

  def attribute_statements
    result = {}
    statements = "name:name|email:email,mail|first_name:first_name,firstname,firstName|last_name:last_name,lastname,lastName|nickname:screenName"
    custom_statements = GlobalSetting.try(:saml_attribute_statements)

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
    omniauth.provider :saml,
                      name: name,
                      issuer: SamlAuthenticator.saml_base_url,
                      idp_sso_target_url: setting(:target_url),
                      idp_slo_target_url: setting(:slo_target_url),
                      slo_default_relay_state: SamlAuthenticator.saml_base_url,
                      idp_cert_fingerprint: GlobalSetting.try(:saml_cert_fingerprint),
                      idp_cert_fingerprint_algorithm: GlobalSetting.try(:saml_cert_fingerprint_algorithm),
                      idp_cert: setting(:cert),
                      idp_cert_multi: setting(:cert_multi),
                      request_attributes: request_attributes,
                      attribute_statements: attribute_statements,
                      assertion_consumer_service_url: SamlAuthenticator.saml_base_url + "/auth/#{name}/callback",
                      single_logout_service_url: SamlAuthenticator.saml_base_url + "/auth/#{name}/slo",
                      name_identifier_format: GlobalSetting.try(:saml_name_identifier_format),
                      custom_url: (GlobalSetting.try(:saml_request_method) == 'post') ? "/discourse_saml" : nil,
                      certificate: GlobalSetting.try(:saml_sp_certificate),
                      private_key: GlobalSetting.try(:saml_sp_private_key),
                      security: {
                        authn_requests_signed: !!GlobalSetting.try(:saml_authn_requests_signed),
                        want_assertions_signed: !!GlobalSetting.try(:saml_want_assertions_signed),
                        logout_requests_signed: !!GlobalSetting.try(:saml_logout_requests_signed),
                        logout_responses_signed: !!GlobalSetting.try(:saml_logout_responses_signed),
                        signature_method: XMLSecurity::Document::RSA_SHA1
                      },
                      idp_slo_session_destroy: proc { |env, session| @user.user_auth_tokens.destroy_all; @user.logged_out }
  end

  def attr(key)
    info[key] || attributes[key]&.join(",") || ""
  end

  def after_authenticate(auth)
    self.info = auth[:info]

    extra_data = auth.extra || {}
    raw_info = extra_data[:raw_info]
    @attributes = raw_info&.attributes || {}

    auth[:uid] = attributes['uid'].try(:first) || auth[:uid] if GlobalSetting.try(:saml_use_attributes_uid)
    uid = auth[:uid]

    auth[:provider] = name
    auth[:info][:email] ||= uid

    result = super

    if GlobalSetting.try(:saml_log_auth)
      ::PluginStore.set("saml", "#{name}_last_auth", auth.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_raw_info", raw_info.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_extra", extra_data.inspect)
    end

    if GlobalSetting.try(:saml_debug_auth)
      data = {
        uid: uid,
        info: info,
        extra: extra_data
      }
      log("#{name}_auth: #{data.inspect}")
    end

    result.username = begin
      if attributes.present?
        username = attributes['screenName'].try(:first)
        username = attributes['uid'].try(:first) if GlobalSetting.try(:saml_use_uid)
      end

      username ||= UserNameSuggester.suggest(result.name) if result.name != uid
      username ||= UserNameSuggester.suggest(result.email) if result.email != uid
      username ||= uid
      username
    end

    result.name = begin
      if attributes.present?
        fullname = attributes['fullName'].try(:first)
        fullname = "#{attributes['firstName'].try(:first)} #{attributes['lastName'].try(:first)}"
      end
      fullname ||= result.name
      fullname
    end

    if result.respond_to?(:skip_email_validation) && GlobalSetting.try(:saml_skip_email_validation)
      result.skip_email_validation = true
    end

    if GlobalSetting.try(:saml_validate_email_fields).present? && attributes['memberOf'].present?
      unless (GlobalSetting.try(:saml_validate_email_fields).split("|").map(&:downcase) & attributes['memberOf'].map(&:downcase)).empty?
        result.email_valid = true
      else
        result.email_valid = false
      end
    elsif GlobalSetting.respond_to?(:saml_default_emails_valid) && !GlobalSetting.saml_default_emails_valid.nil?
      result.email_valid = GlobalSetting.saml_default_emails_valid
    else
      result.email_valid = true
    end

    result.extra_data[:saml_attributes] = attributes
    result.extra_data[:saml_info] = info

    if result.user.blank?
      result.username = '' if GlobalSetting.try(:saml_clear_username)
      result.omit_username = true if GlobalSetting.try(:saml_omit_username)
      result.user = auto_create_account(result) if GlobalSetting.try(:saml_auto_create_account) && result.email_valid
    else
      @user = result.user
      sync_groups
      sync_custom_fields
      sync_email(result.email, uid)
      sync_moderator
      sync_admin
      sync_trust_level
      sync_locale
    end

    result
  end

  def log(info)
    Rails.logger.warn("SAML Debugging: #{info}") if GlobalSetting.try(:saml_debug_auth)
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

  def auto_create_account(result)
    email = result.email
    return if User.find_by_email(email).present?

    # Use a mutex here to counter SAML responses that are sent at the same time and the same email payload
    DistributedMutex.synchronize("discourse_saml_#{email}") do
      try_name = result.name.presence
      try_username = result.username.presence

      user_params = {
        primary_email: UserEmail.new(email: email, primary: true),
        name: try_name || User.suggest_name(try_username || email),
        username: UserNameSuggester.suggest(try_username || try_name || email),
        active: true
      }

      user = User.create!(user_params)
      after_create_account(user, result.as_json.with_indifferent_access)

      user
    end
  end

  def sync_groups
    return unless GlobalSetting.try(:saml_sync_groups)
    groups_fullsync = GlobalSetting.try(:saml_groups_fullsync) || false
    group_attribute = GlobalSetting.try(:saml_groups_attribute) || 'memberOf'
    user_group_list = (attributes[group_attribute] || []).map(&:downcase)

    if GlobalSetting.try(:saml_groups_ldap_leafcn)
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
      total_group_list = (GlobalSetting.try(:saml_sync_groups_list) || "").split('|').map(&:downcase)
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
    statements = GlobalSetting.try(:saml_user_field_statements) || ""

    statements.split("|").each do |statement|
      key, field_id = statement.split(":")
      next if key.blank? || field_id.blank?

      user.custom_fields["user_field_#{field_id}"] = attr(key) if attr(key).present?
    end
  end

  def sync_email(email, uid)
    return unless GlobalSetting.try(:saml_sync_email)

    email = Email.downcase(email)

    return if user.email == email

    existing_user = User.find_by_email(email)
    if email =~ EmailValidator.email_regex && existing_user.nil?
      user.email = email
      user.save

      user.oauth2_user_infos.where(provider: name, uid: uid).update_all(email: email)
    end
  end

  def sync_moderator
    return unless GlobalSetting.try(:saml_sync_moderator)

    is_moderator_attribute = GlobalSetting.try(:saml_moderator_attribute) || 'isModerator'
    is_moderator = ['1', 'true'].include?(attributes[is_moderator_attribute].try(:first).to_s.downcase)

    return if user.moderator == is_moderator

    user.moderator = is_moderator
    user.save
  end

  def sync_admin
    return unless GlobalSetting.try(:saml_sync_admin)

    is_admin_attribute = GlobalSetting.try(:saml_admin_attribute) || 'isAdmin'
    is_admin = ['1', 'true'].include?(attributes[is_admin_attribute].try(:first).to_s.downcase)

    return if user.admin == is_admin

    user.admin = is_admin
    user.save
  end

  def sync_trust_level
    return unless GlobalSetting.try(:saml_sync_trust_level)

    trust_level_attribute = GlobalSetting.try(:saml_trust_level_attribute) || 'trustLevel'
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
    return unless GlobalSetting.try(:saml_sync_locale)

    locale_attribute = GlobalSetting.try(:saml_locale_attribute) || 'locale'
    locale = attributes[locale_attribute].try(:first)

    return unless LocaleSiteSetting.valid_value?(locale)

    if user.locale != locale
      user.locale = locale
      user.save
    end
  end

  def enabled?
    true # SAML plugin has no enabled setting
  end

  def self.saml_base_url
    GlobalSetting.try(:saml_base_url) || Discourse.base_url
  end

end
