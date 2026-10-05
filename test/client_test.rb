require_relative "test_helper"

class ClientTest < Minitest::Test
  def test_env_secret_fallback
    original = ENV["FOIL_SECRET_KEY"]
    ENV["FOIL_SECRET_KEY"] = "sk_env_default"
    fixture = load_fixture("api/sessions/list.json")

    client = Foil::Server::Client.new(
      base_url: "https://example.foil.dev",
      transport: lambda do |_request|
        [200, { "content-type" => "application/json" }, JSON.dump(fixture)]
      end
    )

    assert_equal 1, client.sessions.list.items.length
  ensure
    ENV["FOIL_SECRET_KEY"] = original
  end

  def test_missing_secret_defers_error_until_request
    original = ENV.delete("FOIL_SECRET_KEY")
    client = Foil::Server::Client.new
    assert_respond_to client, :sessions
  ensure
    ENV["FOIL_SECRET_KEY"] = original if original
  end

  def test_secret_endpoints_raise_at_request_time_without_secret
    original = ENV.delete("FOIL_SECRET_KEY")
    client = Foil::Server::Client.new(
      transport: lambda do |_request|
        [200, { "content-type" => "application/json" }, JSON.dump({})]
      end
    )

    assert_raises(Foil::Server::ConfigurationError) do
      client.sessions.list
    end
  ensure
    ENV["FOIL_SECRET_KEY"] = original if original
  end

  def test_base_url_timeout_and_headers_are_applied
    fixture = load_fixture("api/sessions/list.json")
    observed = nil

    client = Foil::Server::Client.new(
      secret_key: "sk_live_test",
      base_url: "https://example.foil.dev",
      timeout: 5,
      user_agent: "custom-foil-ruby",
      transport: lambda do |request|
        observed = request
        [200, { "content-type" => "application/json" }, JSON.dump(fixture)]
      end
    )

    client.sessions.list(limit: 5)
    assert_equal "https://example.foil.dev/v1/sessions?limit=5", observed[:url]
    assert_equal "Bearer sk_live_test", observed[:headers]["Authorization"]
    assert_equal "foil-server-ruby/0.1.0", observed[:headers]["X-Foil-Client"]
    assert_equal "custom-foil-ruby", observed[:headers]["User-Agent"]
    assert_equal 5, client.timeout
  end

  def test_sessions_fingerprints_organizations_and_api_keys
    session_list = load_fixture("api/sessions/list.json")
    session_detail = load_fixture("api/sessions/detail.json")
    fingerprint_list = load_fixture("api/fingerprints/list.json")
    fingerprint_detail = load_fixture("api/fingerprints/detail.json")
    organization_get = load_fixture("api/organizations/organization.json")
    organization_create = load_fixture("api/organizations/organization-create.json")
    organization_update = load_fixture("api/organizations/organization-update.json")
    api_key_create = load_fixture("api/organizations/api-key-create.json")
    api_key_list = load_fixture("api/organizations/api-key-list.json")
    api_key_update = load_fixture("api/organizations/api-key-update.json")
    api_key_rotate = load_fixture("api/organizations/api-key-rotate.json")
    client_user_patch_bodies = []

    client = Foil::Server::Client.new(
      secret_key: "sk_live_test",
      transport: lambda do |request|
        case [request[:method], request[:url]]
        when ["GET", "https://api.usefoil.com/v1/sessions"]
          [200, {}, JSON.dump(session_list)]
        when ["GET", "https://api.usefoil.com/v1/sessions?cursor=cur_sessions_page_2"]
          second_page = {
            data: [
              session_list[:data].first.merge(
                id: "sid_123456789abcdefghjkmnpqrst",
                latest_decision: session_list[:data].first.fetch(:latest_decision).merge(
                  event_id: "evt_3456789abcdefghjkmnpqrstvw",
                  evaluated_at: "2026-03-24T20:01:05.000Z"
                )
              )
            ],
            pagination: {
              limit: 50,
              has_more: false
            },
            meta: {
              request_id: "req_0123456789abcdef0123456789abcdef"
            }
          }
          [200, {}, JSON.dump(second_page)]
        when ["GET", "https://api.usefoil.com/v1/sessions/sid_0123456789abcdefghjkmnpqrs"]
          [200, {}, JSON.dump(session_detail)]
        when ["PATCH", "https://api.usefoil.com/v1/sessions/sid_0123456789abcdefghjkmnpqrs"]
          client_user_patch_bodies << JSON.parse(request[:body])
          [200, {}, JSON.dump(session_detail)]
        when ["GET", "https://api.usefoil.com/v1/fingerprints"]
          [200, {}, JSON.dump(fingerprint_list)]
        when ["GET", "https://api.usefoil.com/v1/fingerprints/vid_456789abcdefghjkmnpqrstvwx"]
          [200, {}, JSON.dump(fingerprint_detail)]
        when ["POST", "https://api.usefoil.com/v1/organizations"]
          [201, {}, JSON.dump(organization_create)]
        when ["GET", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy"]
          [200, {}, JSON.dump(organization_get)]
        when ["PATCH", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy"]
          [200, {}, JSON.dump(organization_update)]
        when ["POST", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys"]
          [201, {}, JSON.dump(api_key_create)]
        when ["GET", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys"]
          [200, {}, JSON.dump(api_key_list)]
        when ["PATCH", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz"]
          [200, {}, JSON.dump(api_key_update)]
        when ["DELETE", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz"]
          [200, {}, JSON.dump(load_fixture("api/organizations/api-key-revoke.json"))]
        when ["POST", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz/rotations"]
          [201, {}, JSON.dump(api_key_rotate)]
        else
          flunk("Unexpected request #{request[:method]} #{request[:url]}")
        end
      end
    )

    assert_equal "sid_0123456789abcdefghjkmnpqrs", client.sessions.get("sid_0123456789abcdefghjkmnpqrs")[:id]
    assert_equal "user_123", client.sessions.get("sid_0123456789abcdefghjkmnpqrs")[:client_user_id]
    assert_equal "sid_0123456789abcdefghjkmnpqrs", client.sessions.attach_client_user("sid_0123456789abcdefghjkmnpqrs", "user_123")[:id]
    assert_equal "sid_0123456789abcdefghjkmnpqrs", client.sessions.clear_client_user("sid_0123456789abcdefghjkmnpqrs")[:id]
    assert_equal [{ "client_user_id" => "user_123" }, { "client_user_id" => nil }], client_user_patch_bodies
    assert_equal ["sid_0123456789abcdefghjkmnpqrs", "sid_123456789abcdefghjkmnpqrst"], client.sessions.iter.map { |item| item[:id] }
    assert_equal "vid_456789abcdefghjkmnpqrstvwx", client.fingerprints.get("vid_456789abcdefghjkmnpqrstvwx")[:id]
    assert_equal "org_56789abcdefghjkmnpqrstvwxy", client.organizations.get("org_56789abcdefghjkmnpqrstvwxy")[:id]
    assert_equal "org_56789abcdefghjkmnpqrstvwxy", client.organizations.create(name: "Example Organization", slug: "example-organization")[:id]
    assert_equal "Example Organization", client.organizations.update("org_56789abcdefghjkmnpqrstvwxy", name: "Updated Example Organization")[:name]
    assert_equal "sk_live_[example_secret_key]", client.organizations.api_keys.create("org_56789abcdefghjkmnpqrstvwxy", name: "Production Backend")[:revealed_key]
    assert_equal "key_6789abcdefghjkmnpqrstvwxyz", client.organizations.api_keys.list("org_56789abcdefghjkmnpqrstvwxy").items.first[:id]
    assert_equal "Updated Web App", client.organizations.api_keys.update("org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz", name: "Updated Web App")[:name]
    assert_equal "key_6789abcdefghjkmnpqrstvwxyz", client.organizations.api_keys.revoke("org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz")[:id]
    assert_equal "sk_live_[rotated_example_secret_key]", client.organizations.api_keys.rotate("org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz")[:revealed_key]
  end

  def test_webhooks_use_event_history_endpoints
    delivery = {
      object: "webhook_delivery",
      id: "wdlv_0123456789abcdef0123456789abcdef",
      event_id: "wevt_0123456789abcdef0123456789abcdef",
      endpoint_id: "we_0123456789abcdef0123456789abcdef",
      event_type: "session.result.persisted",
      status: "succeeded",
      attempts: 1,
      response_status: 200,
      response_body: "{}",
      error: nil,
      created_at: "2026-03-24T20:00:00.000Z",
      updated_at: "2026-03-24T20:00:05.000Z"
    }
    event = {
      object: "event",
      id: "wevt_0123456789abcdef0123456789abcdef",
      type: "session.result.persisted",
      subject: { type: "session", id: "sid_0123456789abcdefghjkmnpqrs" },
      data: { source: "waitForFingerprint" },
      webhook_deliveries: [delivery],
      created_at: "2026-03-24T20:00:00.000Z"
    }

    client = Foil::Server::Client.new(
      secret_key: "sk_live_test",
      transport: lambda do |request|
        assert_equal "Bearer sk_live_test", request[:headers]["Authorization"]
        case [request[:method], request[:url]]
        when ["GET", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events?endpoint_id=we_0123456789abcdef0123456789abcdef&type=session.result.persisted&limit=25"]
          [200, {}, JSON.dump(data: [event], pagination: { limit: 25, has_more: false }, meta: { request_id: "req_0123456789abcdef0123456789abcdef" })]
        when ["GET", "https://api.usefoil.com/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events/wevt_0123456789abcdef0123456789abcdef"]
          [200, {}, JSON.dump(data: event, meta: { request_id: "req_0123456789abcdef0123456789abcdef" })]
        else
          flunk("Unexpected request #{request[:method]} #{request[:url]}")
        end
      end
    )

    events = client.webhooks.list_events(
      "org_56789abcdefghjkmnpqrstvwxy",
      endpoint_id: "we_0123456789abcdef0123456789abcdef",
      type: "session.result.persisted",
      limit: 25
    )
    assert_equal "sid_0123456789abcdefghjkmnpqrs", events.items.first[:subject][:id]
    assert_equal "succeeded", events.items.first[:webhook_deliveries].first[:status]
    assert_equal "session.result.persisted", client.webhooks.retrieve_event("org_56789abcdefghjkmnpqrstvwxy", "wevt_0123456789abcdef0123456789abcdef")[:type]
  end

  def test_api_errors_are_parsed
    %w[
      errors/missing-api-key.json
      errors/invalid-api-key.json
      errors/validation-error.json
      errors/not-found.json
    ].each do |fixture_path|
      fixture = load_fixture(fixture_path)
      client = Foil::Server::Client.new(
        secret_key: "sk_live_test",
        transport: lambda do |_request|
          [fixture.fetch(:error).fetch(:status), { "x-request-id" => fixture.fetch(:error).fetch(:request_id) }, JSON.dump(fixture)]
        end
      )

      error = assert_raises(Foil::Server::ApiError) do
        client.sessions.list(limit: 999)
      end
      assert_equal fixture.fetch(:error).fetch(:code), error.code
      assert_equal fixture.fetch(:error).fetch(:request_id), error.request_id
    end
  end
end
