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
                      issuer: Discourse.base_url,
                      idp_sso_target_url: setting(:target_url),
                      idp_cert_fingerprint: GlobalSetting.try(:saml_cert_fingerprint),
                      idp_cert: setting(:cert),
                      request_attributes: request_attributes,
                      attribute_statements: attribute_statements,
                      assertion_consumer_service_url: Discourse.base_url + "/auth/#{name}/callback",
                      name_identifier_format: GlobalSetting.try(:saml_name_identifier_format),
                      custom_url: (GlobalSetting.try(:saml_request_method) == 'post') ? "/discourse_saml" : nil,
                      certificate: GlobalSetting.try(:saml_sp_certificate),
                      private_key: GlobalSetting.try(:saml_sp_private_key),
                      security: {
                        authn_requests_signed: GlobalSetting.try(:saml_authn_requests_signed) ? true : false,
                        want_assertions_signed: GlobalSetting.try(:saml_want_assertions_signed) ? true : false,
                        signature_method: XMLSecurity::Document::RSA_SHA1
                      }
  end

  def attr(key)
    info[key] || attributes[key]&.join(",") || ""
  end

  def after_authenticate(auth)
    uid = auth[:uid]
    self.info = auth[:info]

    auth[:provider] = name
    auth[:info][:name] ||= uid
    auth[:info][:email] ||= uid

    result = super

    extra_data = auth.extra || {}
    raw_info = extra_data[:raw_info]
    @attributes = raw_info&.attributes || {}

    if GlobalSetting.try(:saml_log_auth)
      ::PluginStore.set("saml", "#{name}_last_auth", auth.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_raw_info", raw_info.inspect)
      ::PluginStore.set("saml", "#{name}_last_auth_extra", extra_data.inspect)
    end

    if GlobalSetting.try(:saml_debug_auth)
      log("#{name}_auth_info: #{info.inspect}")
      log("#{name}_auth_extra: #{extra_data.inspect}")
    end

    result.username = uid
    result.username = attributes['screenName'].try(:first) || uid 
    result.username = attributes['uid'].try(:first) || uid if GlobalSetting.try(:saml_use_uid) && attributes.present?

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

    if GlobalSetting.try(:saml_clear_username) && result.user.blank?
      result.username = ''
    end

    if GlobalSetting.try(:saml_omit_username) && result.user.blank?
      result.omit_username = true
    end

    result.extra_data[:saml_attributes] = attributes
    result.extra_data[:saml_info] = info

    if result.user.present?
      @user = result.user
      sync_groups
      sync_custom_fields
      sync_email(result.email)
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
    sync_custom_fields
  end

  def sync_groups
    return unless GlobalSetting.try(:saml_sync_groups)

    total_group_list = (GlobalSetting.try(:saml_sync_groups_list) || "").split('|')
    user_group_list = attributes['memberOf'] || []
    groups_to_add = user_group_list + attr('groups_to_add').split(",")
    groups_to_remove = attr('groups_to_remove').split(",")

    return if user_group_list.blank? && groups_to_add.blank? && groups_to_remove.blank?

    if total_group_list.present?
      groups_to_add = total_group_list & groups_to_add

      removable_groups = groups_to_remove.dup
      groups_to_remove = total_group_list - groups_to_add
      groups_to_remove &= removable_groups if removable_groups.present?
    end

    Group.where(name: groups_to_add).each do |group|
      group.add user
    end

    Group.where(name: groups_to_remove).each do |group|
      group.remove user
    end
  end

  def sync_custom_fields
    return if user.blank?

    request_attributes.each do |attr|
      key = attr[:name]
      user.custom_fields["#{name}_#{key}"] = attr(key) if attr(key).present?
    end
    user.save_custom_fields
  end

  def sync_email(email)
    return unless GlobalSetting.try(:saml_sync_email)

    email = Email.downcase(email)

    return if user.email == email

    existing_user = User.find_by_email(email)
    if email =~ EmailValidator.email_regex && existing_user.nil?
      user.email = email
      user.save
    end
  end

end
