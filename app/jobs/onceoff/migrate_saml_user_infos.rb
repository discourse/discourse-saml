module Jobs
  class MigrateSamlUserInfos < ::Jobs::Onceoff

    def execute_onceoff(args)
      rows = PluginStoreRow.where(plugin_name: "saml").where("key ~* :pat", pat: '^saml_user_')
      rows.each do |row|
        begin
          Oauth2UserInfo.create(
            uid: row.key.gsub('saml_user_', ''),
            provider: "saml",
            user_id: eval(row.value)[:user_id]
          )
        rescue ActiveRecord::RecordNotUnique => e
          # record already migrated
        end
      end
    end
  end
end
