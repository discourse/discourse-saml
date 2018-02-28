require 'rails_helper'

describe SamlAuthenticator do
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
      PluginStore.set("saml", "saml_user_#{@uid}", {user_id: @user.id })

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
      SiteSetting.saml_request_attributes = "department|title"

      hash = auth_hash(
        'department' => "HR",
        'title' => "Senior HR Manager"
      )

      result = @authenticator.after_authenticate(hash)
      SiteSetting.saml_request_attributes.split("|").each do |name|
        expect(result.user.custom_fields["saml_#{name}"]).to eq(hash.extra.raw_info.attributes[name])
      end
    end

    describe "sync_groups" do

      let(:group_names) { ["group_1", "group_2", "group_3", "group_4"] }

      before do
        GlobalSetting.stubs(:saml_sync_groups).returns(true)
        @groups = group_names.map { |name| Fabricate(:group, name: name) }

        @groups[3].add @user
        @hash = auth_hash(
          'memberOf' => group_names.slice(0, 2),
          'groups_to_add' => group_names.slice(2, 1),
          'groups_to_remove' => group_names.slice(3, 1),
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
  end
end
