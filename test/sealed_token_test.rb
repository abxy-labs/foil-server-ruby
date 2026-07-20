require_relative "test_helper"

class SealedTokenTest < Minitest::Test
  def setup
    require_gate_crypto_support!
  end

  def test_verify_foil_token_with_plaintext_secret
    fixture = load_fixture("sealed-token/vector.v1.json")
    verified = Foil::Server.verify_foil_token(fixture.fetch(:token), fixture.fetch(:secretKey))

    assert_equal fixture.fetch(:payload).fetch(:session_id), verified.fetch(:session_id)
    assert_equal fixture.fetch(:payload).fetch(:decision).fetch(:event_id), verified.fetch(:decision).fetch(:event_id)
  end

  def test_verify_foil_token_with_secret_hash
    fixture = load_fixture("sealed-token/vector.v1.json")
    verified = Foil::Server.verify_foil_token(fixture.fetch(:token), fixture.fetch(:secretHash))

    assert_equal fixture.fetch(:payload).fetch(:decision).fetch(:risk_score), verified.fetch(:decision).fetch(:risk_score)
  end

  def test_verify_multi_recipient_token_with_every_active_key
    fixture = load_fixture("sealed-token/vector.v2.json")

    (fixture.fetch(:secretKeys) + fixture.fetch(:secretHashes)).each do |secret|
      verified = Foil::Server.verify_foil_token(fixture.fetch(:token), secret)
      assert_equal fixture.fetch(:payload).fetch(:session_id), verified.fetch(:session_id)
    end
  end

  def test_safe_verify_foil_token_invalid_fixture
    fixture = load_fixture("sealed-token/invalid.json")
    result = Foil::Server.safe_verify_foil_token(fixture.fetch(:token), "sk_live_fixture_secret")

    refute result[:ok]
    assert_kind_of Foil::Server::TokenVerificationError, result[:error]
  end

  def test_verify_foil_token_requires_secret
    fixture = load_fixture("sealed-token/vector.v1.json")
    original = ENV.delete("FOIL_SECRET_KEY")

    assert_raises(Foil::Server::ConfigurationError) do
      Foil::Server.verify_foil_token(fixture.fetch(:token))
    end
  ensure
    ENV["FOIL_SECRET_KEY"] = original if original
  end
end
