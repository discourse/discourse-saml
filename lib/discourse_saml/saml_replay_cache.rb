# frozen_string_literal: true

module ::DiscourseSaml
  class SamlReplayCache
    CACHE_KEY_PREFIX = "discourse_saml:replay_cache:"
    DEFAULT_ASSERTION_EXPIRY = 10.minutes

    # @param response [OneLogin::RubySaml::Response] SAML response object
    # @return [Boolean] true if this is first time seeing the assertion_id, false if replay
    def self.valid?(response)
      return false if response.blank?

      key = "#{CACHE_KEY_PREFIX}#{response.assertion_id}"
      expiry = calculate_expiry(response)
      return false if expiry.nil?

      result = Discourse.redis.set(key, Time.current.utc.iso8601, nx: true, ex: expiry)
      if result
        if SiteSetting.saml_debug_auth
          Rails.logger.warn("SAML Debugging: #{response.response_id} cached until #{expiry}")
        end
      end

      result
    end

    private

    def self.calculate_expiry(response)
      now = Time.current.utc
      times = []

      times << response.not_on_or_after if response.conditions && response.not_on_or_after
      times << response.session_expires_at if response.session_expires_at
      return DEFAULT_ASSERTION_EXPIRY.to_i if times.empty?

      earliest_expiry = times.min

      # disallow negative/expired windows
      expiry_from_now = earliest_expiry - now
      return nil if expiry_from_now <= 0

      expiry_from_now.to_i
    end
  end
end
