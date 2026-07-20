require "base64"
require "digest"
require "json"
require "openssl"
require "zlib"

module Foil
  module Server
    module SealedToken
      LEGACY_VERSION = 0x01
      MULTI_RECIPIENT_VERSION = 0x02
      NONCE_BYTES = 12
      TAG_BYTES = 16
      CONTENT_KEY_BYTES = 32
      RECIPIENT_ID_BYTES = 32
      MAX_RECIPIENTS = 256
      V2_HEADER_BYTES = 1 + 2 + NONCE_BYTES + 4
      V2_RECIPIENT_BYTES = RECIPIENT_ID_BYTES + NONCE_BYTES + CONTENT_KEY_BYTES + TAG_BYTES
      V2_PAYLOAD_AAD_PREFIX = "foil-sealed-results-v2\0payload\0".b
      V2_WRAP_AAD_PREFIX = "foil-sealed-results-v2\0recipient\0".b

      module_function

      def verify_foil_token(sealed_token, secret_key = nil)
        CryptoSupport.ensure_supported_runtime!
        resolved_secret = secret_key || ENV["FOIL_SECRET_KEY"]
        raise ConfigurationError, "Missing Foil secret key. Pass secret_key explicitly or set FOIL_SECRET_KEY." if resolved_secret.nil? || resolved_secret.empty?

        raw = Base64.decode64(sealed_token)
        raise TokenVerificationError, "Foil token is too short." if raw.bytesize < 29

        compressed = decrypt_payload(raw, resolved_secret)
        payload = JSON.parse(Zlib::Inflate.inflate(compressed))
        deep_symbolize(payload)
      rescue ConfigurationError, TokenVerificationError
        raise
      rescue StandardError => error
        raise TokenVerificationError, "Failed to verify Foil token: #{error.message}"
      end

      def safe_verify_foil_token(sealed_token, secret_key = nil)
        { ok: true, data: verify_foil_token(sealed_token, secret_key) }
      rescue ConfigurationError, TokenVerificationError => error
        { ok: false, error: error }
      end

      def derive_key(secret_key_or_hash)
        Digest::SHA256.digest("#{normalize_secret(secret_key_or_hash)}\0sealed-results")
      end
      private_class_method :derive_key

      def decrypt_gcm(ciphertext, key, nonce, tag, aad = "".b)
        cipher = OpenSSL::Cipher.new("aes-256-gcm")
        cipher.decrypt
        cipher.key = key
        cipher.iv = nonce
        cipher.auth_tag = tag
        cipher.auth_data = aad
        cipher.update(ciphertext) + cipher.final
      end
      private_class_method :decrypt_gcm

      def decrypt_payload(raw, secret_key)
        version = raw.getbyte(0)
        if version == LEGACY_VERSION
          return decrypt_gcm(
            raw.byteslice(13, raw.bytesize - 29),
            derive_key(secret_key),
            raw.byteslice(1, NONCE_BYTES),
            raw.byteslice(raw.bytesize - TAG_BYTES, TAG_BYTES)
          )
        end
        raise TokenVerificationError, "Unsupported Foil token version: #{version}" unless version == MULTI_RECIPIENT_VERSION
        raise TokenVerificationError, "Foil token is too short." if raw.bytesize < V2_HEADER_BYTES + TAG_BYTES + V2_RECIPIENT_BYTES

        recipient_count = raw.byteslice(1, 2).unpack1("n")
        raise TokenVerificationError, "Foil token has an invalid recipient count." unless recipient_count.between?(1, MAX_RECIPIENTS)

        payload_length = raw.byteslice(15, 4).unpack1("N")
        payload_start = V2_HEADER_BYTES
        payload_tag_start = payload_start + payload_length
        recipients_start = payload_tag_start + TAG_BYTES
        expected_length = recipients_start + (recipient_count * V2_RECIPIENT_BYTES)
        raise TokenVerificationError, "Foil token has an invalid length." if payload_length < 1 || expected_length != raw.bytesize

        expected_id = Digest::SHA256.digest("#{normalize_secret(secret_key)}\0sealed-results-recipient-id")
        recipient_ids = recipient_count.times.map do |index|
          raw.byteslice(
            recipients_start + (index * V2_RECIPIENT_BYTES),
            RECIPIENT_ID_BYTES
          )
        end.join
        content_key = nil
        recipient_count.times do |index|
          entry_start = recipients_start + (index * V2_RECIPIENT_BYTES)
          recipient_id = raw.byteslice(entry_start, RECIPIENT_ID_BYTES)
          next unless OpenSSL.fixed_length_secure_compare(recipient_id, expected_id)

          nonce_start = entry_start + RECIPIENT_ID_BYTES
          wrapped_key_start = nonce_start + NONCE_BYTES
          tag_start = wrapped_key_start + CONTENT_KEY_BYTES
          content_key = decrypt_gcm(
            raw.byteslice(wrapped_key_start, CONTENT_KEY_BYTES),
            derive_key(secret_key),
            raw.byteslice(nonce_start, NONCE_BYTES),
            raw.byteslice(tag_start, TAG_BYTES),
            V2_WRAP_AAD_PREFIX + recipient_id
          )
          break
        end
        raise TokenVerificationError, "Secret key is not a recipient of this Foil token." unless content_key&.bytesize == CONTENT_KEY_BYTES

        decrypt_gcm(
          raw.byteslice(payload_start, payload_length),
          content_key,
          raw.byteslice(3, NONCE_BYTES),
          raw.byteslice(payload_tag_start, TAG_BYTES),
          V2_PAYLOAD_AAD_PREFIX + raw.byteslice(0, V2_HEADER_BYTES) + recipient_ids
        )
      end
      private_class_method :decrypt_payload

      def normalize_secret(secret_key_or_hash)
        return secret_key_or_hash.downcase if /\A[0-9a-fA-F]{64}\z/.match?(secret_key_or_hash)

        Digest::SHA256.hexdigest(secret_key_or_hash)
      end
      private_class_method :normalize_secret

      def deep_symbolize(value)
        case value
        when Array
          value.map { |item| deep_symbolize(item) }
        when Hash
          value.each_with_object({}) do |(key, item), memo|
            memo[key.to_sym] = deep_symbolize(item)
          end
        else
          value
        end
      end
      private_class_method :deep_symbolize
    end
  end
end
