# frozen_string_literal: true

describe SamlAuthenticator do
  let!(:authenticator) { SamlAuthenticator.new }
  let!(:uid) { 123_456 }

  fab!(:user)

  describe "after_authenticate" do
    def auth_hash(attributes)
      OmniAuth::AuthHash.new(
        provider: "saml",
        uid:,
        info: {
          name: user.name,
          email: user.email,
        },
        extra: {
          raw_info: OneLogin::RubySaml::Attributes.new(attributes),
        },
      )
    end

    it "finds user by email" do
      hash =
        OmniAuth::AuthHash.new(
          provider: "saml",
          uid: "654321",
          info: {
            name: user.name,
            email: user.email,
          },
        )

      result = authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(user.email)
    end

    it "finds user by uid" do
      Fabricate(:saml_user_info, provider_uid: uid, user:)

      hash =
        OmniAuth::AuthHash.new(
          provider: "saml",
          uid:,
          info: {
            name: user.name,
            email: "john_doe@example.com",
          },
        )

      result = authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(user.email)
      expect(result.email_valid).to eq(true)
    end

    it "finds user by email in uid" do
      Fabricate(:saml_user_info, provider_uid: uid, user:)

      hash = OmniAuth::AuthHash.new(provider: "saml", uid: user.email, info: {})

      result = authenticator.after_authenticate(hash)
      expect(result.user).to eq(user)
    end

    it "defaults email_valid to false if saml_default_emails_valid is false" do
      SiteSetting.saml_default_emails_valid = false

      Fabricate(:saml_user_info, provider_uid: uid, user:)

      hash =
        OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name: user.name, email: user.email })

      result = authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(user.email)
      expect(result.email_valid).to eq(false)
    end

    it "defaults email_valid based on saml_validate_email_fields setting" do
      SiteSetting.saml_validate_email_fields = "customers"

      hash = auth_hash("memberOf" => %w[Customers Employees])

      result = authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(user.email)
      expect(result.email_valid).to eq(true)
    end

    it "stores additional request attributes to user custom fields" do
      SiteSetting.saml_request_attributes = "department|title"

      hash = auth_hash("department" => %w[HR Manager], "title" => ["Senior HR Manager"])

      result = authenticator.after_authenticate(hash)
      SiteSetting
        .saml_request_attributes
        .split("|")
        .each do |name|
          expect(result.user.custom_fields["saml_#{name}"]).to eq(
            hash.extra.raw_info[name].join(","),
          )
        end
    end

    it "syncs user fields based on `saml_user_field_statements` environment variable" do
      SiteSetting.saml_user_field_statements = "department:2|title:3"

      hash = auth_hash("department" => %w[HR Manager], "title" => ["Senior HR Manager"])

      result = authenticator.after_authenticate(hash)
      attrs = hash.extra.raw_info

      SiteSetting
        .saml_user_field_statements
        .split("|")
        .each do |statement|
          key, id = statement.split(":")
          expect(result.user.custom_fields["user_field_#{id}"]).to eq(attrs[key].join(","))
        end
    end

    it "syncs user locale" do
      SiteSetting.saml_sync_locale = true
      user_locale = "fr"

      hash = auth_hash("locale" => [user_locale])

      result = authenticator.after_authenticate(hash)
      hash.extra.raw_info.attributes

      expect(result.user.locale).to eq(user_locale)
    end

    it "should get uid value from extra attributes param" do
      SiteSetting.saml_use_attributes_uid = true

      hash = auth_hash("uid" => ["789"])

      authenticator.after_authenticate(hash)
      expect(UserAssociatedAccount.last.provider_uid).to eq("789")
    end

    context "when automatically creating a new account" do
      before { SiteSetting.saml_auto_create_account = true }

      it "creates a new account and a UserAssociatedAccount record" do
        name = "John Doe"
        email = "johndoe@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, email: email })
        result = authenticator.after_authenticate(hash)

        expect(result.user.name).to eq(name)
        expect(result.user.email).to eq(email)
        expect(result.user.username).to eq("John_Doe")
        expect(result.user.active).to eq(true)
        expect(result.user.id).to eq(
          UserAssociatedAccount.find_by(
            provider_uid: uid,
            provider_name: authenticator.name,
          ).user_id,
        )
      end

      it "ignores invalid input when generating username" do
        SiteSetting.unicode_usernames = false

        nickname = "άκυρος"
        name = "john"
        email = "johndoe@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, nickname:, email: })
        result = authenticator.after_authenticate(hash)

        expect(result.user.username).to eq(name) # ignores nickname and uses name
      end

      it "use email as a source for username if enabled in settings" do
        SiteSetting.use_email_for_username_and_name_suggestions = true

        nickname = ""
        name = ""
        email = "johndoe@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, nickname:, email: })
        result = authenticator.after_authenticate(hash)

        expect(result.user.username).to eq("johndoe") # "johndoe" was extracted from email
      end

      it "by default does not use email as a source for username" do
        nickname = ""
        name = ""
        email = "johndoe@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, nickname:, email: })
        result = authenticator.after_authenticate(hash)

        expect(result.user.username).to eq(uid.to_s) # not "johndoe" that can be extracted from email
      end

      it "if name is present uses it for name" do
        name = "John Doe"
        nickname = "john"
        email = "johnmail@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, nickname:, email: })
        result = authenticator.after_authenticate(hash)

        expect(result.user.name).to eq(name)
      end

      it "uses nickname as name if name is not present" do
        name = ""
        nickname = "john"
        email = "johnmail@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, nickname:, email: })
        result = authenticator.after_authenticate(hash)

        expect(result.user.name).to eq("John")
      end

      it "does not use email as a source for name suggestions by default" do
        name = ""
        nickname = ""
        email = "johnmail@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, nickname:, email: })
        result = authenticator.after_authenticate(hash)

        # not "mail" extracted from email
        expect(result.user.name).to eq("")
      end

      it "uses email as a source for name suggestions if enabled in settings" do
        SiteSetting.use_email_for_username_and_name_suggestions = true

        name = ""
        nickname = ""
        email = "johnmail@example.com"

        hash = OmniAuth::AuthHash.new(provider: "saml", uid:, info: { name:, nickname:, email: })
        result = authenticator.after_authenticate(hash)

        expect(result.user.name).to eq("Johnmail")
      end
    end

    describe "username" do
      let(:name) { "John Doe" }
      let(:email) { "johndoe@example.com" }
      let(:screen_name) { "johndoe" }
      let(:hash) do
        OmniAuth::AuthHash.new(
          provider: "saml",
          uid:,
          info: {
            name:,
            email:,
            nickname: screen_name,
          },
          extra: {
            raw_info:
              OneLogin::RubySaml::Attributes.new(
                uid: [uid.to_s.split(",")],
                screenName: [screen_name.split(",")],
              ),
          },
        )
      end

      it "should be equal to uid" do
        SiteSetting.saml_use_attributes_uid = true

        result = authenticator.after_authenticate(hash)
        expect(result.username).to eq(uid.to_s)
      end

      it "should be equal to nickname, which omniauth-saml calculated from screenName" do
        result = authenticator.after_authenticate(hash)
        expect(result.username).to eq(screen_name)
      end
    end

    describe "name" do
      it "prefers firstname_lastname" do
        hash =
          OmniAuth::AuthHash.new(
            provider: "saml",
            uid:,
            info: {
              name: "Banana Split",
              email: "not@used.co",
              first_name: "Apple",
              last_name: "Pie",
            },
            extra: {
              raw_info: {
                attributes: {
                },
              },
            },
          )
        result = authenticator.after_authenticate(hash)
        expect(result.name).to eq("Apple Pie")
      end

      it "falls back to name attribute if no first_name and last_name" do
        hash =
          OmniAuth::AuthHash.new(
            provider: "saml",
            uid:,
            info: {
              name: "Banana Split",
              email: "not@used.co",
            },
            extra: {
              raw_info: {
                attributes: {
                },
              },
            },
          )
        result = authenticator.after_authenticate(hash)
        expect(result.name).to eq("Banana Split")
      end
    end

    describe "Group Syncing" do
      fab!(:group1) { Fabricate(:group, name: "uno", full_name: "Group One") }
      fab!(:group2) { Fabricate(:group, name: "dos", full_name: "Group Two") }
      fab!(:group_without_fullname) { Fabricate(:group, name: "tres") }
      fab!(:original_group) do
        Fabricate(:group, name: "original_group", full_name: "The Origin").tap { |g| g.add(user) }
      end

      before { SiteSetting.saml_sync_groups = true }

      describe "sync_groups" do
        it "sync users to the given groups" do
          hash =
            auth_hash(
              "memberOf" => [group1.name, group2.name],
              "groups_to_add" => [group_without_fullname.name],
              "groups_to_remove" => [original_group.name],
            )

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            group1.name,
            group2.name,
            group_without_fullname.name,
          )
        end

        it "sync users to the given groups within scope" do
          SiteSetting.saml_sync_groups_list = [
            group2.name,
            group_without_fullname.name,
            original_group.name,
          ].join("|")
          hash =
            auth_hash(
              "memberOf" => [group1.name, group2.name],
              "groups_to_add" => [group_without_fullname.name],
              "groups_to_remove" => [original_group.name],
            )

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            group2.name,
            group_without_fullname.name,
          )
        end
      end

      describe "sync_groups with LDAP leaf cn" do
        let!(:group1_ldap) { "cn=#{group1.name},cn=groups,dc=example,dc=com" }
        let!(:group2_ldap) { "cn=#{group2.name},cn=groups,dc=example,dc=com" }
        let!(:group_without_fullname_ldap) do
          "cn=#{group_without_fullname.name},cn=groups,dc=example,dc=com"
        end
        let!(:original_group_ldap) { "cn=#{original_group.name},cn=groups,dc=example,dc=com" }

        before { SiteSetting.saml_groups_ldap_leafcn = true }

        it "sync users to the given ldap groups in `memberOf`" do
          hash =
            auth_hash(
              "memberOf" => [group1_ldap, group2_ldap],
              "groups_to_add" => [group_without_fullname.name],
              "groups_to_remove" => [original_group.name],
            )

          expect(user.groups.pluck(:name)).to contain_exactly(original_group.name)

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            group1.name,
            group2.name,
            group_without_fullname.name,
          )
        end

        it "sync users to the groups within scope" do
          SiteSetting.saml_sync_groups_list = [
            group2.name,
            group_without_fullname.name,
            original_group.name,
          ].join("|")

          hash =
            auth_hash(
              "memberOf" => [group1_ldap, group2_ldap],
              "groups_to_add" => [group_without_fullname.name],
              "groups_to_remove" => [original_group.name],
            )

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            group2.name,
            group_without_fullname.name,
          )
        end
      end

      describe "sync_groups with fullsync" do
        let(:group_names) { %w[uno dos tres original] }

        before { SiteSetting.saml_groups_fullsync = true }

        it "full sync with a user who has no group membership currently" do
          hash = auth_hash("memberOf" => [group1.name, group2.name])

          result = authenticator.after_authenticate(hash)

          expect(result.user.groups.pluck(:name)).to contain_exactly(group1.name, group2.name)
        end

        it "full sync, ignoring values in group list and groups_to_add/groups_to_remove" do
          SiteSetting.saml_sync_groups_list = [group2.name, group_without_fullname.name].join("|")

          hash =
            auth_hash(
              "memberOf" => [group1.name, group2.name],
              "groups_to_add" => [original_group.name],
              "groups_to_remove" => [group_without_fullname.name],
            )

          result = authenticator.after_authenticate(hash)

          expect(result.user.groups.pluck(:name)).to contain_exactly(group1.name, group2.name)
        end
      end

      describe "saml_groups_attribute" do
        it "syncs groups from the saml_groups_attribute setting" do
          SiteSetting.saml_groups_attribute = "notTheDefault"
          hash = auth_hash("notTheDefault" => [group1.name, group2.name])

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            original_group.name,
            group1.name,
            group2.name,
          )
        end

        it "removes groups from the previously saved saml_groups_attributes in raw_info" do
          SiteSetting.saml_groups_attribute = "notTheDefault"

          # user's existing group associations and user_associated_account
          group1.add(user)
          user.user_associated_accounts.create!(
            provider_name: "saml",
            provider_uid: uid,
            user:,
            extra: {
              raw_info: {
                "memberOf" => [group_without_fullname.name], # this is ignored as it is not the correct attribute
                "notTheDefault" => [group1.name], # this is the correct attribute
              },
            },
          )

          # new auth hash with a different group
          hash = auth_hash("notTheDefault" => [group2.name])

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            # group1 should be removed
            original_group.name,
            group2.name,
          )
        end

        it "allows the attribute to specify an array, and assigns groups from those attributes" do
          SiteSetting.saml_groups_attribute = "Country|Hemisphere"
          hash =
            auth_hash(
              "Country" => [group1.name, group2.name],
              "Hemisphere" => [group_without_fullname.name],
            )

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            original_group.name,
            group1.name,
            group2.name,
            group_without_fullname.name,
          )
        end
      end

      describe "saml_groups_use_full_name" do
        before { SiteSetting.saml_groups_use_full_name = true }

        it "adds users to groups based on group's case insensitive full_names" do
          SiteSetting.saml_groups_attribute = "oneAttribute|twoAttribute" # ensure compat
          SiteSetting.saml_sync_groups_list = [group1.full_name, group2.full_name].join("|") # ensure compat

          hash =
            auth_hash(
              "oneAttribute" => [group1.full_name.upcase, "I don't exist"],
              "twoAttribute" => [group2.full_name],
            )

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(
            group1.name,
            group2.name,
            original_group.name,
          )
        end

        it "is compatible with full_sync" do
          SiteSetting.saml_groups_use_full_name = true
          SiteSetting.saml_groups_fullsync = true

          hash = auth_hash("memberOf" => [group1.full_name])

          result = authenticator.after_authenticate(hash)
          expect(result.user.groups.pluck(:name)).to contain_exactly(group1.name)
        end
      end
    end

    describe "set moderator" do
      before { SiteSetting.saml_sync_moderator = true }

      it "user should be a moderator (default param)" do
        hash = auth_hash("isModerator" => [1])
        result = authenticator.after_authenticate(hash)
        user = result.user

        expect(user.moderator).to eq(true)
        expect(user.groups.pluck(:name)).to include("moderators", "staff")
      end

      it "user should be a moderator (using specified saml_moderator_attribute)" do
        SiteSetting.saml_moderator_attribute = "is_a_moderator"
        hash = auth_hash("is_a_moderator" => ["true"])
        result = authenticator.after_authenticate(hash)
        expect(result.user.moderator).to eq(true)
      end
    end

    describe "set admin" do
      before { SiteSetting.saml_sync_admin = true }

      it "user should be an admin (default param)" do
        hash = auth_hash("isAdmin" => [1])
        result = authenticator.after_authenticate(hash)
        user = result.user

        expect(user.admin).to eq(true)
        expect(user.groups.pluck(:name)).to include("admins", "staff")
      end

      it "user should be an admin (using specified saml_admin_attribute)" do
        SiteSetting.saml_admin_attribute = "is_an_admin"
        hash = auth_hash("is_an_admin" => ["true"])
        result = authenticator.after_authenticate(hash)
        expect(result.user.admin).to eq(true)
      end
    end

    describe "set trust_level" do
      before { SiteSetting.saml_sync_trust_level = true }

      it "user should have trust level 3 (default param)" do
        hash = auth_hash("trustLevel" => [3])
        result = authenticator.after_authenticate(hash)
        user = result.user

        expect(user.trust_level).to eq(3)
        expect(user.manual_locked_trust_level).to eq(3)
        expect(user.groups.pluck(:name)).to include(
          "trust_level_1",
          "trust_level_2",
          "trust_level_3",
        )
      end

      it "user should have trust level 3 (using specified saml_trust_level_attribute)" do
        SiteSetting.saml_trust_level_attribute = "my_trust_level"
        hash = auth_hash("my_trust_level" => ["3"])
        result = authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(3)
        expect(result.user.manual_locked_trust_level).to eq(3)
      end

      it "user should get lower trust level" do
        user.trust_level = 4
        hash = auth_hash("trustLevel" => [1])
        result = authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(1)
        expect(result.user.manual_locked_trust_level).to eq(1)
      end

      it "invalid trust levels should not be used" do
        user.trust_level = 1
        hash = auth_hash("trustLevel" => [15])
        result = authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(1)
      end
    end

    describe "global setting" do
      it "matches request_attributes count" do
        expect(authenticator.request_attributes.count).to eq(4)

        SiteSetting.saml_request_attributes = "company_name|mobile_number|name"
        expect(authenticator.request_attributes.count).to eq(6)
      end

      it "matches attribute_statements count" do
        expect(authenticator.attribute_statements.count).to eq(5)

        SiteSetting.saml_attribute_statements = "email:emailAddress|company|name"
        expect(authenticator.attribute_statements.count).to eq(5)
        expect(authenticator.attribute_statements["email"]).to eq(%w[email mail emailAddress])

        SiteSetting.saml_attribute_statements =
          "company_name:company,business|phone:mobile,contact_no"
        expect(authenticator.attribute_statements.count).to eq(7)
      end
    end

    describe "after_create_account" do
      fab!(:group)

      it "adds to group" do
        SiteSetting.saml_sync_groups = true
        authenticator = SamlAuthenticator.new
        auth_hash =
          OmniAuth::AuthHash.new(provider: "saml", uid: "123", info: { groups_to_add: group.name })

        result = authenticator.after_authenticate(auth_hash)

        user = Fabricate(:user, email: "realgoogleuser@gmail.com")

        session_data = result.session_data
        after_create_result = Auth::Result.from_session_data(session_data, user:)

        authenticator.after_create_account(user, after_create_result)

        expect(user.groups.find(group.id).present?).to eq(true)
      end
    end
  end

  describe ".base_url" do
    it "works" do
      expect(SamlAuthenticator.saml_base_url).to eq("http://test.localhost")
    end

    it "can be overridden by a setting" do
      SiteSetting.saml_base_url = "https://override.example.com"
      expect(SamlAuthenticator.saml_base_url).to eq("https://override.example.com")
    end
  end
end
