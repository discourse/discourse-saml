require 'rails_helper'

describe SamlAuthenticator do
  context 'after_authenticate' do
    before do
      @authenticator = SamlAuthenticator.new('saml')
      @uid = 123456
      @user = Fabricate(:user)
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

      hash = OmniAuth::AuthHash.new(
        uid: @uid,
        info: {
            name: "John Doe",
            email: @user.email
        },
        extra: {
          raw_info: OneLogin::RubySaml::Attributes.new({
            'memberOf' => %w(Customers Employees)
          })
        }
      )

      result = @authenticator.after_authenticate(hash)
      expect(result.user.email).to eq(@user.email)
      expect(result.email_valid).to eq(true)
    end
  end
end
