# frozen_string_literal: true

class ::DiscourseSaml::SamlOmniauthStrategy < OmniAuth::Strategies::SAML
  option :request_method, "GET"

  def request_phase
    if options[:request_method] == "POST"
      render_auto_submitted_form
    else
      super
    end
  end

  private

  def render_auto_submitted_form
    authn_request = OneLogin::RubySaml::Authrequest.new
    with_settings do |settings|
      saml_req = authn_request.create_params(settings, additional_params_for_authn_request)["SAMLRequest"]
      destination_url = settings.idp_sso_service_url

      script_url = UrlHelper.absolute('/plugins/discourse-saml/javascripts/submit-form-on-load.js', GlobalSetting.cdn_url)

      html = <<~HTML
        <html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en">
          <body>
            <noscript>
              <p>
                <strong>Note:</strong> Since your browser does not support JavaScript,
                you must press the Continue button once to proceed.
              </p>
            </noscript>
            <form action="#{destination_url}" method="post">
              <div>
                <input type="hidden" name="SAMLRequest" value="#{saml_req}"/>
              </div>
              <noscript>
                <div>
                  <input type="submit" value="Continue"/>
                </div>
              </noscript>
            </form>
            <script src="#{script_url}"></script>
          </body>
        </html>
      HTML

      r = Rack::Response.new
      r.write(html)
      r.finish
    end
  end
end
