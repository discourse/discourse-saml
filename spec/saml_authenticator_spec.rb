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

    describe "sync_groups" do

      let(:group_names) { ["group_1", "group_2", "group_3", "group_4"] }

      before do
        GlobalSetting.stubs(:saml_sync_groups).returns(true)
        @groups = group_names.map { |name| Fabricate(:group, name: name) }

        @groups[3].add @user
        @hash = auth_hash(
          'memberOf' => group_names.slice(0, 2),
          'groups_to_add' => [group_names.slice(2, 1).join(",")],
          'groups_to_remove' => [group_names.slice(3, 1).join(",")],
        )
      end

      it 'sync users to the given groups' do
        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to eq(group_names.slice(0, 3))
      end

      it 'sync users to the given groups within scope' do
        GlobalSetting.stubs(:saml_sync_groups_list).returns(group_names.slice(1, 3).join("|"))

        result = @authenticator.after_authenticate(@hash)
        expect(result.user.groups.pluck(:name)).to eq(group_names.slice(1, 2))
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
