require_relative "test_helper"

class WebhooksTest < Minitest::Test
  def fixture
    @fixture ||= JSON.parse(File.read(File.join(__dir__, "..", "spec", "fixtures", "webhooks", "signature.json")))
  end

  def verify(**overrides)
    Foil::Server::Webhooks.verify_webhook_signature(
      **{
        secret: fixture["secret"],
        timestamp: fixture["timestamp"],
        raw_body: fixture["raw_body"],
        signature: fixture["signature"],
        now_seconds: fixture["now_seconds"]
      }.merge(overrides)
    )
  end

  def test_valid_signature_verifies
    assert verify
  end

  def test_tampered_signature_body_or_secret_is_rejected
    refute verify(signature: fixture["invalid_signature"])
    refute verify(signature: "short")
    refute verify(raw_body: "#{fixture["raw_body"]} ")
    refute verify(secret: "whsec_other")
  end

  def test_expired_and_malformed_timestamps_are_rejected
    refute verify(timestamp: fixture["expired_timestamp"])
    refute verify(timestamp: "not-a-timestamp")
    refute verify(timestamp: nil)
  end

  def test_custom_max_age_is_honored
    assert verify(now_seconds: fixture["now_seconds"] + 600, max_age_seconds: 900)
  end

  def test_parse_session_result_persisted_event
    event = Foil::Server::Webhooks.parse_webhook_event(fixture["raw_body"])

    assert_equal "webhook_event", event[:object]
    assert_equal "session.result.persisted", event[:type]
    assert_equal "wevt_0123456789abcdef0123456789abcdef", event[:id]
    assert_equal "sid_0123456789abcdefghjkmnpqrs", event[:data][:session][:id]
  end

  def test_parse_webhook_test_event
    event = Foil::Server::Webhooks.parse_webhook_event(JSON.dump(
      id: "wevt_0123456789abcdefghjkmnpqrs",
      object: "webhook_event",
      type: "webhook.test",
      created: "2026-04-27T00:00:00.000Z",
      data: {}
    ))

    assert_equal "webhook.test", event[:type]
  end

  def test_parse_rejects_unsupported_or_malformed_events
    base = {
      id: "wevt_0123456789abcdefghjkmnpqrs",
      object: "webhook_event",
      type: "session.result.persisted",
      created: "2026-04-27T00:00:00.000Z",
      data: {}
    }

    assert_raises(ArgumentError) { Foil::Server::Webhooks.parse_webhook_event(JSON.dump(base.merge(type: "unknown.event"))) }
    assert_raises(ArgumentError) { Foil::Server::Webhooks.parse_webhook_event(JSON.dump(base.merge(object: "event"))) }
    assert_raises(ArgumentError) { Foil::Server::Webhooks.parse_webhook_event(JSON.dump(base.merge(data: []))) }
    assert_raises(ArgumentError) { Foil::Server::Webhooks.parse_webhook_event(JSON.dump([base])) }
  end

  def test_verify_and_parse_checks_signature_first
    event = Foil::Server::Webhooks.verify_and_parse_webhook_event(
      secret: fixture["secret"],
      timestamp: fixture["timestamp"],
      raw_body: fixture["raw_body"],
      signature: fixture["signature"],
      now_seconds: fixture["now_seconds"]
    )
    assert_equal "session.result.persisted", event[:type]

    error = assert_raises(ArgumentError) do
      Foil::Server::Webhooks.verify_and_parse_webhook_event(
        secret: fixture["secret"],
        timestamp: fixture["timestamp"],
        raw_body: fixture["raw_body"],
        signature: fixture["invalid_signature"],
        now_seconds: fixture["now_seconds"]
      )
    end
    assert_equal "Invalid Foil webhook signature", error.message
  end

  def test_helpers_are_available_on_the_top_level_module
    assert Foil::Server.verify_webhook_signature(
      secret: fixture["secret"],
      timestamp: fixture["timestamp"],
      raw_body: fixture["raw_body"],
      signature: fixture["signature"],
      now_seconds: fixture["now_seconds"]
    )
    assert_equal "session.result.persisted", Foil::Server.parse_webhook_event(fixture["raw_body"])[:type]
    assert_equal "session.result.persisted", Foil::Server.verify_and_parse_webhook_event(
      secret: fixture["secret"],
      timestamp: fixture["timestamp"],
      raw_body: fixture["raw_body"],
      signature: fixture["signature"],
      now_seconds: fixture["now_seconds"]
    )[:type]
  end
end
