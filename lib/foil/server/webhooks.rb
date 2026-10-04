require "json"
require "openssl"

module Foil
  module Server
    module Webhooks
      WEBHOOK_EVENT_TYPES = %w[
        session.fingerprint.calculated
        session.result.persisted
        webhook.test
      ].freeze

      module_function

      def verify_webhook_signature(secret:, timestamp:, raw_body:, signature:, max_age_seconds: 300, now_seconds: nil)
        parsed_timestamp = Integer(timestamp)
        current = now_seconds || Time.now.to_i
        return false if (current - parsed_timestamp).abs > max_age_seconds

        expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{raw_body}")
        secure_compare(expected, signature.to_s)
      rescue ArgumentError, TypeError
        false
      end

      def parse_webhook_event(raw_body)
        envelope = symbolize(JSON.parse(raw_body))
        raise ArgumentError, "webhook event envelope must be an object" unless envelope.is_a?(Hash)
        raise ArgumentError, "webhook event object must be webhook_event" unless envelope[:object] == "webhook_event"
        raise ArgumentError, "webhook event id is required" if envelope[:id].to_s.empty?
        raise ArgumentError, "webhook event type is required" if envelope[:type].to_s.empty?
        raise ArgumentError, "unsupported webhook event type: #{envelope[:type]}" unless WEBHOOK_EVENT_TYPES.include?(envelope[:type])
        raise ArgumentError, "webhook event created timestamp is required" if envelope[:created].to_s.empty?
        raise ArgumentError, "webhook event data must be an object" unless envelope[:data].is_a?(Hash)

        envelope
      end

      def verify_and_parse_webhook_event(secret:, timestamp:, raw_body:, signature:, max_age_seconds: 300, now_seconds: nil)
        unless verify_webhook_signature(secret: secret, timestamp: timestamp, raw_body: raw_body, signature: signature, max_age_seconds: max_age_seconds, now_seconds: now_seconds)
          raise ArgumentError, "Invalid Foil webhook signature"
        end
        parse_webhook_event(raw_body)
      end

      def symbolize(value)
        case value
        when Array
          value.map { |item| symbolize(item) }
        when Hash
          value.each_with_object({}) do |(key, item), memo|
            memo[key.to_sym] = symbolize(item)
          end
        else
          value
        end
      end
      private_class_method :symbolize

      def secure_compare(left, right)
        return false unless left.bytesize == right.bytesize

        result = 0
        left.bytes.zip(right.bytes) { |a, b| result |= a ^ b }
        result.zero?
      end
      private_class_method :secure_compare
    end
  end
end
