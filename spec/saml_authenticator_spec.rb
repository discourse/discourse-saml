require 'rails_helper'

describe SamlAuthenticator do
  Fabricator(:oauth2_user_info) do
    provider "saml"
    user
  end

  context 'after_authenticate' do
    before do
      @authenticator = SamlAuthenticator.new('saml')
      @uid = 123456
      @user = Fabricate(:user)
    end

    def auth_hash(attributes)
      hash = OmniAuth::AuthHash.new(
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
      Fabricate(:oauth2_user_info, uid: @uid, user: @user)

      hash = OmniAuth::AuthHash.new(
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
      Fabricate(:oauth2_user_info, uid: @uid, user: @user)

      hash = OmniAuth::AuthHash.new(
        uid: @user.email,
        info: {}
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user).to eq(@user)
    end

    it 'defaults email_valid to false if saml_default_emails_valid is false' do
      GlobalSetting.stubs(:saml_default_emails_valid).returns(false)

      hash = OmniAuth::AuthHash.new(
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
      GlobalSetting.stubs(:saml_validate_email_fields).returns("customers")

      hash = auth_hash(
        'memberOf' => %w(Customers Employees)
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(@user.email)
      expect(result.email_valid).to eq(true)
    end

    it 'stores additional request attributes to user custom fields' do
      GlobalSetting.stubs(:saml_request_attributes).returns("department|title")

      hash = auth_hash(
        'department' => ["HR", "Manager"],
        'title' => ["Senior HR Manager"]
      )

      result = @authenticator.after_authenticate(hash)
      GlobalSetting.saml_request_attributes.split("|").each do |name|
        expect(result.user.custom_fields["saml_#{name}"]).to eq(hash.extra.raw_info.attributes[name].join(","))
      end
    end

    it 'should get uid value from extra attributes param' do
      GlobalSetting.stubs(:saml_use_attributes_uid).returns("true")

      hash = auth_hash('uid' => ["789"])

      @authenticator.after_authenticate(hash)
      expect(Oauth2UserInfo.last.uid).to eq("789")
    end

    it 'creates new account automatically' do
      GlobalSetting.stubs(:saml_auto_create_account).returns(true)
      name = "John Doe"
      email = "johndoe@example.com"

      hash = OmniAuth::AuthHash.new(
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
      expect(result.user.id).to eq(Oauth2UserInfo.find_by(uid: @uid, provider: @authenticator.name).user_id)
    end

    describe "username" do
      let(:name) { "John Doe" }
      let(:email) { "johndoe@example.com" }
      let(:screen_name) { "johndoe" }
      let(:hash) { OmniAuth::AuthHash.new(
          uid: @uid,
          info: {
              name: name,
              email: email
          },
          extra: {
            raw_info: {
              attributes: {
                uid: @uid.to_s.split(","),
                screenName: screen_name.split(",")
              }
            }
          }
        )
      }

      it 'should be equal to uid' do
        GlobalSetting.stubs(:saml_use_uid).returns(true)

        result = @authenticator.after_authenticate(hash)
        expect(result.username).to eq(@uid.to_s)
      end

      it 'should be equal to screenName' do
        result = @authenticator.after_authenticate(hash)
        expect(result.username).to eq(screen_name)
      end

      it 'should be populated from name' do
        hash.extra = nil

        result = @authenticator.after_authenticate(hash)
        expect(result.username).to eq(name.sub(" ", "_"))
      end

      it 'should be populated from email' do
        hash.extra = nil
        hash.info.name = nil

        result = @authenticator.after_authenticate(hash)
        expect(result.username).to eq(email.split("@")[0])
      end
    end

    describe "sync_groups" do

      let(:group_names) { ["group_1", "Group_2", "GROUP_3", "group_4"] }

      before do
        GlobalSetting.stubs(:saml_sync_groups).returns(true)
        @groups = group_names.map { |name| Fabricate(:group, name: name.downcase) }

        @groups[3].add @user
        @hash = auth_hash(
          'memberOf' => group_names.slice(0, 2),
          'groups_to_add' => [group_names.slice(2, 1).join(",")],
          'groups_to_remove' => [group_names.slice(3, 1).join(",")],
        )
      end

      it 'sync users to the given groups' do
        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to eq(group_names.slice(0, 3).map(&:downcase))
      end

      it 'sync users to the given groups within scope' do
        GlobalSetting.stubs(:saml_sync_groups_list).returns(group_names.slice(1, 3).join("|"))

        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to eq(group_names.slice(1, 2).map(&:downcase))
      end

    end

    describe "set moderator" do
      before do
        GlobalSetting.stubs(:saml_sync_moderator).returns(true)
      end

      it 'user should be a moderator (default param)' do
        hash = auth_hash(
          'isModerator' => [1],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.moderator).to eq(true)
      end

      it 'user should be a moderator (using specified saml_moderator_attribute)' do
        GlobalSetting.stubs(:saml_moderator_attribute).returns('is_a_moderator')
        hash = auth_hash(
          'is_a_moderator' => ['true'],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.moderator).to eq(true)
      end
    end

    describe "set trust_level" do
      before do
        GlobalSetting.stubs(:saml_sync_trust_level).returns(true)
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
        GlobalSetting.stubs(:saml_trust_level_attribute).returns('my_trust_level')
        hash = auth_hash(
          'my_trust_level' => ['3'],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(3)
        expect(result.user.manual_locked_trust_level).to eq(3)
      end

      it 'user should get lower trust level' do
        @user.trust_level = 4;
        hash = auth_hash(
          'trustLevel' => [1],
        )
        result = @authenticator.after_authenticate(hash)
        expect(result.user.trust_level).to eq(1)
        expect(result.user.manual_locked_trust_level).to eq(1)
      end

      it 'invalid trust levels should not be used' do
        @user.trust_level = 1;
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

        GlobalSetting.stubs(:saml_request_attributes).returns("company_name|mobile_number|name")
        expect(@authenticator.request_attributes.count).to eq(6)
      end

      it "matches attribute_statements count" do
        expect(@authenticator.attribute_statements.count).to eq(5)

        GlobalSetting.stubs(:saml_attribute_statements).returns("email:emailAddress|company|name")
        expect(@authenticator.attribute_statements.count).to eq(5)
        expect(@authenticator.attribute_statements["email"]).to eq(["email", "mail", "emailAddress"])

        GlobalSetting.stubs(:saml_attribute_statements).returns("company_name:company,business|phone:mobile,contact_no")
        expect(@authenticator.attribute_statements.count).to eq(7)
      end
    end

    context 'after_create_account' do
      it 'adds to group' do
        GlobalSetting.stubs(:saml_sync_groups).returns(true)
        authenticator = SamlAuthenticator.new("saml", trusted: true)
        user = Fabricate(:user, email: 'realgoogleuser@gmail.com')
        group = Fabricate(:group)
        session = {
          extra_data: {
            uid: "123456",
            provider: "saml",
            saml_info: {
              groups_to_add: group.name
            },
            saml_attributes: {
              name: "John Doe",
              email: user.email
            }
          }
        }
        authenticator.after_create_account(user, session)
        expect(user.groups.find(group.id).present?).to eq(true)
      end
    end
  end
end
