# frozen_string_literal: true

Fabricator(:saml_user_info, class_name: :user_associated_account) do
  provider_name "saml"
  user
end
