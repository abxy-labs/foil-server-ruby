require "base64"
require "digest"
require "json"
require "openssl"

module Foil
  module Server
    module GateDelivery
      GATE_DELIVERY_VERSION = 1
      GATE_DELIVERY_ALGORITHM = "x25519-hkdf-sha256/aes-256-gcm"
      GATE_AGENT_TOKEN_ENV_SUFFIX = "_GATE_AGENT_TOKEN"
      BLOCKED_GATE_ENV_VAR_KEYS = %w[
        BASH_ENV
        BROWSER
        CDPATH
        DYLD_INSERT_LIBRARIES
        DYLD_LIBRARY_PATH
        EDITOR
        ENV
        GIT_ASKPASS
        GIT_SSH_COMMAND
        HOME
        LD_LIBRARY_PATH
        LD_PRELOAD
        NODE_OPTIONS
        NODE_PATH
        PATH
        PERL5OPT
        PERLLIB
        PROMPT_COMMAND
        PYTHONHOME
        PYTHONPATH
        PYTHONSTARTUP
        RUBYLIB
        RUBYOPT
        SHELLOPTS
        SSH_ASKPASS
        VISUAL
        XDG_CONFIG_HOME
      ].freeze
      BLOCKED_GATE_ENV_VAR_PREFIXES = %w[NPM_CONFIG_ BUN_CONFIG_ GIT_CONFIG_].freeze
      WEBHOOK_EVENT_TYPES = %w[
        session.fingerprint.calculated
        session.result.persisted
        gate.session.approved
        webhook.test
      ].freeze
      GATE_DELIVERY_HKDF_INFO = "foil-gate-delivery:v1".b.freeze
      X25519_SPKI_PREFIX = ["302a300506032b656e032100"].pack("H*").freeze

      module_function

      def derive_gate_agent_token_env_key(service_id)
        normalized = service_id.to_s.strip.gsub(/[^A-Za-z0-9]+/, "_").gsub(/^_+|_+$/, "").gsub(/_+/, "_").upcase
        raise ArgumentError, "service_id is required to derive a Gate agent token env key" if normalized.empty?

        return "FOIL#{GATE_AGENT_TOKEN_ENV_SUFFIX}" if ["FOIL", "FOIL"].include?(normalized)

        "#{normalized}#{GATE_AGENT_TOKEN_ENV_SUFFIX}"
      end

      def is_gate_managed_env_var_key(key)
        key == "FOIL_AGENT_TOKEN" || key.to_s.end_with?(GATE_AGENT_TOKEN_ENV_SUFFIX)
      end

      def is_blocked_gate_env_var_key(key)
        normalized = key.to_s.strip.upcase
        BLOCKED_GATE_ENV_VAR_KEYS.include?(normalized) || BLOCKED_GATE_ENV_VAR_PREFIXES.any? { |prefix| normalized.start_with?(prefix) }
      end

      def raw_x25519_public_key_from_key_object(public_key)
        if public_key.respond_to?(:raw_public_key)
          raw_public_key = public_key.raw_public_key
          raise ArgumentError, "X25519 public key must be 32 bytes" unless raw_public_key.bytesize == 32

          return raw_public_key
        end

        der = public_key.public_to_der
        raise ArgumentError, "Unexpected X25519 public key encoding" unless der.bytesize == X25519_SPKI_PREFIX.bytesize + 32
        raise ArgumentError, "Unexpected X25519 public key prefix" unless der.byteslice(0, X25519_SPKI_PREFIX.bytesize) == X25519_SPKI_PREFIX

        der.byteslice(X25519_SPKI_PREFIX.bytesize, 32)
      end

      def key_id_for_raw_x25519_public_key(raw_public_key)
        raise ArgumentError, "X25519 public key must be 32 bytes" unless raw_public_key.bytesize == 32

        Base64.urlsafe_encode64(Digest::SHA256.digest(raw_public_key), padding: false)
      end

      def create_delivery_key_pair
        CryptoSupport.ensure_supported_runtime!
        private_key = OpenSSL::PKey.generate_key("X25519")
        raw_public_key = raw_x25519_public_key_from_key_object(private_key)
        {
          delivery: {
            version: GATE_DELIVERY_VERSION,
            algorithm: GATE_DELIVERY_ALGORITHM,
            key_id: key_id_for_raw_x25519_public_key(raw_public_key),
            public_key: Base64.urlsafe_encode64(raw_public_key, padding: false)
          },
          private_key: private_key
        }
      end

      def export_delivery_private_key_pkcs8(private_key)
        CryptoSupport.ensure_supported_runtime!
        Base64.urlsafe_encode64(private_key.private_to_der, padding: false)
      end

      def import_delivery_private_key_pkcs8(value)
        CryptoSupport.ensure_supported_runtime!
        OpenSSL::PKey.read(b64url_decode(value, "delivery.private_key_pkcs8"))
      end

      def validate_gate_delivery_request(value)
        candidate = symbolize(value)
        raise ArgumentError, "delivery.version must be 1" unless candidate[:version] == GATE_DELIVERY_VERSION
        raise ArgumentError, "delivery.algorithm must be #{GATE_DELIVERY_ALGORITHM}" unless candidate[:algorithm] == GATE_DELIVERY_ALGORITHM
        raise ArgumentError, "delivery.public_key is required" if candidate[:public_key].to_s.empty?
        raise ArgumentError, "delivery.key_id is required" if candidate[:key_id].to_s.empty?

        raw_public_key = b64url_decode(candidate[:public_key], "delivery.public_key")
        raise ArgumentError, "delivery.public_key must be a raw X25519 public key" unless raw_public_key.bytesize == 32
        raise ArgumentError, "delivery.key_id does not match delivery.public_key" unless key_id_for_raw_x25519_public_key(raw_public_key) == candidate[:key_id]

        {
          version: GATE_DELIVERY_VERSION,
          algorithm: GATE_DELIVERY_ALGORITHM,
          key_id: candidate[:key_id],
          public_key: candidate[:public_key]
        }
      end

      def create_encrypted_delivery_response(input)
        {
          encrypted_delivery: encrypt_gate_delivery_payload(
            input.fetch(:delivery),
            {
              version: GATE_DELIVERY_VERSION,
              outputs: input.fetch(:outputs)
            }
          )
        }
      end

      def create_gate_approved_webhook_response(input)
        create_encrypted_delivery_response(input)
      end

      def validate_encrypted_gate_delivery_envelope(value)
        candidate = symbolize(value)
        raise ArgumentError, "encrypted_delivery.version must be 1" unless candidate[:version] == GATE_DELIVERY_VERSION
        raise ArgumentError, "encrypted_delivery.algorithm must be #{GATE_DELIVERY_ALGORITHM}" unless candidate[:algorithm] == GATE_DELIVERY_ALGORITHM
        %i[key_id ephemeral_public_key salt iv ciphertext tag].each do |field|
          raise ArgumentError, "encrypted_delivery.#{field} is required" if candidate[field].to_s.empty?
        end
        raise ArgumentError, "encrypted_delivery.ephemeral_public_key must be 32 bytes" unless b64url_decode(candidate[:ephemeral_public_key], "encrypted_delivery.ephemeral_public_key").bytesize == 32
        raise ArgumentError, "encrypted_delivery.salt must be 32 bytes" unless b64url_decode(candidate[:salt], "encrypted_delivery.salt").bytesize == 32
        raise ArgumentError, "encrypted_delivery.iv must be 12 bytes" unless b64url_decode(candidate[:iv], "encrypted_delivery.iv").bytesize == 12
        raise ArgumentError, "encrypted_delivery.tag must be 16 bytes" unless b64url_decode(candidate[:tag], "encrypted_delivery.tag").bytesize == 16

        candidate
      end

      def encrypt_gate_delivery_payload(delivery, payload)
        CryptoSupport.ensure_supported_runtime!
        validated_delivery = validate_gate_delivery_request(delivery)
        payload = symbolize(payload)
        raise ArgumentError, "Gate delivery payload version must be 1" unless payload[:version] == GATE_DELIVERY_VERSION

        recipient_public_key = OpenSSL::PKey.read(X25519_SPKI_PREFIX + b64url_decode(validated_delivery[:public_key], "delivery.public_key"))
        ephemeral_private_key = OpenSSL::PKey.generate_key("X25519")
        shared_secret = ephemeral_private_key.derive(recipient_public_key)
        salt = OpenSSL::Random.random_bytes(32)
        iv = OpenSSL::Random.random_bytes(12)
        key = OpenSSL::KDF.hkdf(shared_secret, salt: salt, info: GATE_DELIVERY_HKDF_INFO, length: 32, hash: "SHA256")

        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.encrypt
        cipher.key = key
        cipher.iv = iv
        ciphertext = cipher.update(JSON.generate(compact_payload(payload))) + cipher.final
        tag = cipher.auth_tag

        {
          version: GATE_DELIVERY_VERSION,
          algorithm: GATE_DELIVERY_ALGORITHM,
          key_id: validated_delivery[:key_id],
          ephemeral_public_key: Base64.urlsafe_encode64(raw_x25519_public_key_from_key_object(ephemeral_private_key), padding: false),
          salt: Base64.urlsafe_encode64(salt, padding: false),
          iv: Base64.urlsafe_encode64(iv, padding: false),
          ciphertext: Base64.urlsafe_encode64(ciphertext, padding: false),
          tag: Base64.urlsafe_encode64(tag, padding: false)
        }
      end

      def decrypt_gate_delivery_envelope(private_key, envelope)
        CryptoSupport.ensure_supported_runtime!
        validated = validate_encrypted_gate_delivery_envelope(envelope)
        shared_secret = private_key.derive(
          OpenSSL::PKey.read(X25519_SPKI_PREFIX + b64url_decode(validated[:ephemeral_public_key], "encrypted_delivery.ephemeral_public_key"))
        )
        key = OpenSSL::KDF.hkdf(
          shared_secret,
          salt: b64url_decode(validated[:salt], "encrypted_delivery.salt"),
          info: GATE_DELIVERY_HKDF_INFO,
          length: 32,
          hash: "SHA256"
        )
        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.decrypt
        cipher.key = key
        cipher.iv = b64url_decode(validated[:iv], "encrypted_delivery.iv")
        cipher.auth_tag = b64url_decode(validated[:tag], "encrypted_delivery.tag")
        cipher.auth_data = ""
        plaintext = cipher.update(b64url_decode(validated[:ciphertext], "encrypted_delivery.ciphertext")) + cipher.final
        payload = JSON.parse(plaintext)
        raise ArgumentError, "encrypted_delivery payload must be an object" unless payload.is_a?(Hash)

        symbolize(payload).tap do |candidate|
          raise ArgumentError, "encrypted_delivery payload version must be 1" unless candidate[:version] == GATE_DELIVERY_VERSION
          raise ArgumentError, "encrypted_delivery payload outputs must be an object" unless candidate[:outputs].is_a?(Hash)
          candidate[:outputs].each do |key_name, item|
            raise ArgumentError, "encrypted_delivery output #{key_name} must be a string" unless item.is_a?(String)
          end
        end
      rescue JSON::ParserError
        raise ArgumentError, "encrypted_delivery decrypted to invalid JSON"
      end

      def validate_gate_approved_webhook_payload(value)
        candidate = symbolize(value)
        raise ArgumentError, "webhook payload must not include event; use the webhook event envelope type" if candidate.key?(:event)
        raise ArgumentError, "service_id is required" if candidate[:service_id].to_s.empty?
        raise ArgumentError, "gate_session_id is required" if candidate[:gate_session_id].to_s.empty?
        raise ArgumentError, "gate_account_id is required" if candidate[:gate_account_id].to_s.empty?
        raise ArgumentError, "account_name is required" if candidate[:account_name].to_s.empty?
        raise ArgumentError, "metadata must be an object or null" unless candidate[:metadata].nil? || candidate[:metadata].is_a?(Hash)
        raise ArgumentError, "foil must be an object" unless candidate[:foil].is_a?(Hash)
        verdict = candidate[:foil][:verdict]
        raise ArgumentError, "foil.verdict is invalid" unless %w[bot human inconclusive].include?(verdict)
        score = candidate[:foil][:score]
        raise ArgumentError, "foil.score must be a number or null" unless score.nil? || score.is_a?(Numeric)

        {
          service_id: candidate[:service_id],
          gate_session_id: candidate[:gate_session_id],
          gate_account_id: candidate[:gate_account_id],
          account_name: candidate[:account_name],
          metadata: candidate[:metadata]&.dup,
          foil: {
            verdict: verdict,
            score: score
          },
          delivery: validate_gate_delivery_request(candidate[:delivery])
        }
      end

      def verify_gate_webhook_signature(secret:, timestamp:, raw_body:, signature:, max_age_seconds: 300, now_seconds: nil)
        parsed_timestamp = Integer(timestamp)
        current = now_seconds || Time.now.to_i
        return false if (current - parsed_timestamp).abs > max_age_seconds

        expected = OpenSSL::HMAC.hexdigest("SHA256", secret, "#{timestamp}.#{raw_body}")
        secure_compare(expected, signature)
      rescue ArgumentError
        false
      end

      def parse_webhook_event(raw_body)
        envelope = symbolize(JSON.parse(raw_body))
        raise ArgumentError, "webhook event object must be webhook_event" unless envelope[:object] == "webhook_event"
        raise ArgumentError, "webhook event id is required" if envelope[:id].to_s.empty?
        raise ArgumentError, "webhook event type is required" if envelope[:type].to_s.empty?
        raise ArgumentError, "unsupported webhook event type: #{envelope[:type]}" unless WEBHOOK_EVENT_TYPES.include?(envelope[:type])
        raise ArgumentError, "webhook event created timestamp is required" if envelope[:created].to_s.empty?
        raise ArgumentError, "webhook event data must be an object" unless envelope[:data].is_a?(Hash)

        envelope[:data] = validate_gate_approved_webhook_payload(envelope[:data]) if envelope[:type] == "gate.session.approved"
        envelope
      end

      def verify_and_parse_webhook_event(secret:, timestamp:, raw_body:, signature:, max_age_seconds: 300, now_seconds: nil)
        unless verify_gate_webhook_signature(secret: secret, timestamp: timestamp, raw_body: raw_body, signature: signature, max_age_seconds: max_age_seconds, now_seconds: now_seconds)
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

      def compact_payload(payload)
        {
          version: payload[:version],
          outputs: payload[:outputs],
          **(payload[:ack_token] ? { ack_token: payload[:ack_token] } : {})
        }
      end
      private_class_method :compact_payload

      def b64url_decode(value, label)
        Base64.urlsafe_decode64(value.to_s)
      rescue ArgumentError => error
        raise ArgumentError, "Invalid #{label}: #{error.message}"
      end
      private_class_method :b64url_decode

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
