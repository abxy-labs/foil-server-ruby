require_relative "server/version"
require_relative "server/errors"
require_relative "server/crypto_support"
require_relative "server/types"
require_relative "server/sealed_token"
require_relative "server/webhooks"
require_relative "server/client"

module Foil
  module Server
    module_function

    def verify_foil_token(sealed_token, secret_key = nil)
      SealedToken.verify_foil_token(sealed_token, secret_key)
    end

    def safe_verify_foil_token(sealed_token, secret_key = nil)
      SealedToken.safe_verify_foil_token(sealed_token, secret_key)
    end

    def verify_webhook_signature(**options)
      Webhooks.verify_webhook_signature(**options)
    end

    def parse_webhook_event(raw_body)
      Webhooks.parse_webhook_event(raw_body)
    end

    def verify_and_parse_webhook_event(**options)
      Webhooks.verify_and_parse_webhook_event(**options)
    end
  end
end
