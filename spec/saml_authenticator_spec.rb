# frozen_string_literal: true

require 'rails_helper'

describe SamlAuthenticator do
  Fabricator(:saml_user_info, class_name: :user_associated_account) do
    provider_name "saml"
    user
  end

  context 'after_authenticate' do
    before do
      @authenticator = SamlAuthenticator.new
      @uid = 123456
      @user = Fabricate(:user)
    end

    def auth_hash(attributes)
      hash = OmniAuth::AuthHash.new(
        provider: "saml",
        uid: @uid,
        info: {
            name: "John Doe",
            email: @user.email
        },
        extra: {
          raw_info: OneLogin::RubySaml::Attributes.new(attributes)
        }
      )
    end

    it 'finds user by email' do
      hash = OmniAuth::AuthHash.new(
        provider: "saml",
        uid: "654321",
        info: {
            name: "John Doe",
            email: @user.email
        }
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(@user.email)
    end

    it 'finds user by uid' do
      Fabricate(:saml_user_info, provider_uid: @uid, user: @user)

      hash = OmniAuth::AuthHash.new(
        provider: "saml",
        uid: @uid,
        info: {
            name: "John Doe",
            email: "john_doe@example.com"
        }
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(@user.email)
      expect(result.email_valid).to eq(true)
    end

    it 'finds user by email in uid' do
      Fabricate(:saml_user_info, provider_uid: @uid, user: @user)

      hash = OmniAuth::AuthHash.new(
        provider: "saml",
        uid: @user.email,
        info: {}
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user).to eq(@user)
    end

    it 'defaults email_valid to false if saml_default_emails_valid is false' do
      SiteSetting.saml_default_emails_valid = false

      Fabricate(:saml_user_info, provider_uid: @uid, user: @user)

      hash = OmniAuth::AuthHash.new(
        provider: "saml",
        uid: @uid,
        info: {
            name: "John Doe",
            email: @user.email
        }
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(@user.email)
      expect(result.email_valid).to eq(false)
    end

    it 'defaults email_valid based on saml_validate_email_fields setting' do
      SiteSetting.saml_validate_email_fields = "customers"

      hash = auth_hash(
        'memberOf' => %w(Customers Employees)
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(@user.email)
      expect(result.email_valid).to eq(true)
    end

    it 'stores additional request attributes to user custom fields' do
      SiteSetting.saml_request_attributes = "department|title"

      hash = auth_hash(
        'department' => ["HR", "Manager"],
        'title' => ["Senior HR Manager"]
      )

      result = @authenticator.after_authenticate(hash)
      SiteSetting.saml_request_attributes.split("|").each do |name|
        expect(result.user.custom_fields["saml_#{name}"]).to eq(hash.extra.raw_info.multi(name).join(","))
      end
    end

    it 'syncs user fields based on `saml_user_field_statements` environment variable' do
      SiteSetting.saml_user_field_statements = "department:2|title:3"

      hash = auth_hash(
        'department' => ["HR", "Manager"],
        'title' => ["Senior HR Manager"]
      )

      result = @authenticator.after_authenticate(hash)
      attrs = hash.extra.raw_info

      SiteSetting.saml_user_field_statements.split("|").each do |statement|
        key, id = statement.split(":")
        expect(result.user.custom_fields["user_field_#{id}"]).to eq(attrs.multi(key).join(","))
      end
    end

    it 'syncs user locale' do
      SiteSetting.saml_sync_locale = true
      user_locale = "fr"

      hash = auth_hash(
        'locale' => [user_locale]
      )

      result = @authenticator.after_authenticate(hash)
      attrs = hash.extra.raw_info.attributes

      expect(result.user.locale).to eq(user_locale)
    end

    it 'should get uid value from extra attributes param' do
      SiteSetting.saml_use_attributes_uid = true

      hash = auth_hash('uid' => ["789"])

      @authenticator.after_authenticate(hash)
      expect(UserAssociatedAccount.last.provider_uid).to eq("789")
    end

    it 'creates new account automatically' do
      SiteSetting.saml_auto_create_account = true
      name = "John Doe"
      email = "johndoe@example.com"

      hash = OmniAuth::AuthHash.new(
        provider: "saml",
        uid: @uid,
        info: {
            name: name,
            email: email
        }
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.name).to eq(name)
      expect(result.user.email).to eq(email)
      expect(result.user.username).to eq("John_Doe")
      expect(result.user.active).to eq(true)
      expect(result.user.id).to eq(UserAssociatedAccount.find_by(provider_uid: @uid, provider_name: @authenticator.name).user_id)
    end

    it 'ignores invalid input when automatically creating new account' do
      SiteSetting.saml_auto_create_account = true
      SiteSetting.unicode_usernames = false

      nickname = "άκυρος"
      name = "άκυρος"
      email = "johndoe@example.com"

      hash = OmniAuth::AuthHash.new(
        provider: "saml",
        uid: @uid,
        info: {
          name: name,
          nickname: nickname,
          email: email
        }
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.username).to eq("johndoe")
    end

    describe "username" do
      let(:name) { "John Doe" }
      let(:email) { "johndoe@example.com" }
      let(:screen_name) { "johndoe" }
      let(:hash) { OmniAuth::AuthHash.new(
          provider: "saml",
          uid: @uid,
          info: {
              name: name,
              email: email,
              nickname: screen_name,
          },
          extra: {
            raw_info: OneLogin::RubySaml::Attributes.new(
                uid: [@uid.to_s.split(",")],
                screenName: [screen_name.split(",")]
            )
          }
        )
      }

      it 'should be equal to uid' do
        SiteSetting.saml_use_attributes_uid = true

        result = @authenticator.after_authenticate(hash)
        expect(result.username).to eq(@uid.to_s)
      end

      it 'should be equal to nickname, which omniauth-saml calculated from screenName' do
        result = @authenticator.after_authenticate(hash)
        expect(result.username).to eq(screen_name)
      end
    end

    describe "name" do
      let(:name) { "John Doe" }
      let(:first_name) { "Jane" }
      let(:last_name) { "Smith" }
      let(:email) { "johndoe@example.com" }
      let(:screen_name) { "johndoe" }
      let(:hash) { OmniAuth::AuthHash.new(
          provider: "saml",
          uid: @uid,
          info: {
              name: name,
              email: email,
              first_name: first_name,
              last_name: last_name,
              nickname: screen_name
          },
          extra: {
            raw_info: {
              attributes: {
              }
            }
          }
        )
      }

      it "should prefer firstname_lastname" do
        result = @authenticator.after_authenticate(hash)
        expect(result.name).to eq("#{first_name} #{last_name}")
      end

      it "should fallback to `name`" do
        hash.info.delete(:first_name)
        hash.info.delete(:last_name)
        result = @authenticator.after_authenticate(hash)
        expect(result.name).to eq(name)
      end

    end

    describe "sync_groups" do
      let(:group_names) { ["group_1", "Group_2", "GROUP_3", "group_4"] }

      before do
        SiteSetting.saml_sync_groups = true
        @groups = group_names.map { |name| Fabricate(:group, name: name.downcase) }

        @groups[3].add @user
        @hash = auth_hash(
          'memberOf' => group_names[0..1],
          'groups_to_add' => [group_names[2]],
          'groups_to_remove' => [group_names[3]],
        )
      end

      it 'sync users to the given groups' do
        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to match_array(group_names[0..2].map(&:downcase))
      end

      it 'sync users to the given groups within scope' do
        SiteSetting.saml_sync_groups_list = group_names[1..3].join("|")

        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to match_array(group_names[1..2].map(&:downcase))
      end
    end

    describe "sync_groups with LDAP leaf cn" do
      let(:group_names) { ["group_1", "Group_2", "GROUP_3", "group_4"] }
      let(:group_names_ldap) { ["cn=group_1,cn=groups,dc=example,dc=com", "cn=Group_2,cn=groups,dc=example,dc=com", "cn=GROUP_3,cn=groups,dc=example,dc=com", "cn=group_4,cn=groups,dc=example,dc=com"] }

      before do
        SiteSetting.saml_sync_groups = true
        SiteSetting.saml_groups_ldap_leafcn = true
        @groups = group_names.map { |name| Fabricate(:group, name: name.downcase) }

        @groups[3].add @user
        @hash = auth_hash(
          'memberOf' => group_names_ldap[0..1],
          'groups_to_add' => [group_names[2]],
          'groups_to_remove' => [group_names[3]],
        )
      end

      it 'sync users to the given groups' do
        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to match_array(group_names[0..2].map(&:downcase))
      end

      it 'sync users to the given groups within scope' do
        SiteSetting.saml_sync_groups_list = group_names[1..3].join("|")

        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to match_array(group_names[1..2].map(&:downcase))
      end
    end

    describe "sync_groups with fullsync" do
      let(:group_names) { ["group_1", "Group_2", "GROUP_3", "group_4"] }

      before do
        SiteSetting.saml_sync_groups = true
        SiteSetting.saml_groups_fullsync = true
        @groups = group_names.map { |name| Fabricate(:group, name: name.downcase) }

        @hash = auth_hash(
          'memberOf' => group_names[0..1]
        )
      end

      it 'full sync with a user who has no group membership currently' do
        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to match_array(group_names[0..1].map(&:downcase))
      end

      it 'sync users to the given groups' do
        @groups[0].add @user
        @groups[3].add @user
        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to match_array(group_names[0..1].map(&:downcase))
      end
    end

    describe "set moderator" do
      before do
        SiteSetting.saml_sync_moderator = true
      end

      it 'user should be a moderator (default param)' do
        hash = auth_hash(
          'isModerator' => [1],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.moderator).to eq(true)
      end

      it 'user should be a moderator (using specified saml_moderator_attribute)' do
        SiteSetting.saml_moderator_attribute = 'is_a_moderator'
        hash = auth_hash(
          'is_a_moderator' => ['true'],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.moderator).to eq(true)
      end
    end

    describe "set admin" do
      before do
        SiteSetting.saml_sync_admin = true
      end

      it 'user should be an admin (default param)' do
        hash = auth_hash(
          'isAdmin' => [1],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.admin).to eq(true)
      end

      it 'user should be an admin (using specified saml_admin_attribute)' do
        SiteSetting.saml_admin_attribute = 'is_an_admin'
        hash = auth_hash(
          'is_an_admin' => ['true'],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.admin).to eq(true)
      end
    end

    describe "set trust_level" do
      before do
        SiteSetting.saml_sync_trust_level = true
      end

      it 'user should have trust level 3 (default param)' do
        hash = auth_hash(
          'trustLevel' => [3],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(3)
        expect(result.user.manual_locked_trust_level).to eq(3)
      end

      it 'user should have trust level 3 (using specified saml_trust_level_attribute)' do
        SiteSetting.saml_trust_level_attribute = 'my_trust_level'
        hash = auth_hash(
          'my_trust_level' => ['3'],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(3)
        expect(result.user.manual_locked_trust_level).to eq(3)
      end

      it 'user should get lower trust level' do
        @user.trust_level = 4
        hash = auth_hash(
          'trustLevel' => [1],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(1)
        expect(result.user.manual_locked_trust_level).to eq(1)
      end

      it 'invalid trust levels should not be used' do
        @user.trust_level = 1
        hash = auth_hash(
          'trustLevel' => [15],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(1)
      end
    end

    describe "global setting" do
      it "matches request_attributes count" do
        expect(@authenticator.request_attributes.count).to eq(4)

        SiteSetting.saml_request_attributes = "company_name|mobile_number|name"
        expect(@authenticator.request_attributes.count).to eq(6)
      end

      it "matches attribute_statements count" do
        expect(@authenticator.attribute_statements.count).to eq(5)

        SiteSetting.saml_attribute_statements = "email:emailAddress|company|name"
        expect(@authenticator.attribute_statements.count).to eq(5)
        expect(@authenticator.attribute_statements["email"]).to eq(["email", "mail", "emailAddress"])

        SiteSetting.saml_attribute_statements = "company_name:company,business|phone:mobile,contact_no"
        expect(@authenticator.attribute_statements.count).to eq(7)
      end
    end

    context 'after_create_account' do
      let(:group) { Fabricate(:group) }
      let(:auth_hash) {
        OmniAuth::AuthHash.new(
          provider: "saml",
          uid: "123",
          info: {
            groups_to_add: group.name
          },
        )
      }

      it 'adds to group' do
        SiteSetting.saml_sync_groups = true
        authenticator = SamlAuthenticator.new

        result = authenticator.after_authenticate(auth_hash)

        user = Fabricate(:user, email: 'realgoogleuser@gmail.com')

        session_data = result.session_data
        after_create_result = Auth::Result.from_session_data(session_data, user: user)

        authenticator.after_create_account(user, after_create_result)

        expect(user.groups.find(group.id).present?).to eq(true)
      end
    end
  end

  describe ".base_url" do
    it "works" do
      expect(SamlAuthenticator.saml_base_url).to eq("http://test.localhost")
    end

    it "can be overriden by a setting" do
      SiteSetting.saml_base_url = "https://override.example.com"
      expect(SamlAuthenticator.saml_base_url).to eq("https://override.example.com")
    end
  end
end
