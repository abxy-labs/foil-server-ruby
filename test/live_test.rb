require_relative "test_helper"

class LiveTest < Minitest::Test
  def test_public_server_surface
    skip "Set FOIL_LIVE_SMOKE=1 to run live smoke tests." unless ENV["FOIL_LIVE_SMOKE"] == "1"

    client = Foil::Server::Client.new(
      secret_key: require_env("FOIL_SMOKE_SECRET_KEY"),
      base_url: env_or_default("FOIL_SMOKE_BASE_URL", "https://api.usefoil.com")
    )
    organization_id = require_env("FOIL_SMOKE_ORGANIZATION_ID")

    created_key_id = nil
    rotated_key_id = nil

    begin
      sessions = client.sessions.list(limit: 1)
      refute_empty sessions.items, "Smoke organization must have at least one session for the live smoke suite."
      session = client.sessions.get(sessions.items.first.fetch(:id))
      assert_equal sessions.items.first.fetch(:id), session.fetch(:id)

      fingerprints = client.fingerprints.list(limit: 1)
      refute_empty fingerprints.items, "Smoke organization must have at least one fingerprint for the live smoke suite."
      fingerprint = client.fingerprints.get(fingerprints.items.first.fetch(:id))
      assert_equal fingerprints.items.first.fetch(:id), fingerprint.fetch(:id)

      organization = client.organizations.get(organization_id)
      updated_organization = client.organizations.update(organization_id, name: organization.fetch(:name), status: organization.fetch(:status))
      assert_equal organization.fetch(:name), updated_organization.fetch(:name)
      assert_equal organization.fetch(:status), updated_organization.fetch(:status)

      created_key = client.organizations.api_keys.create(
        organization_id,
        name: "sdk-smoke-#{(Time.now.to_f * 1000).to_i.to_s(16)}",
        environment: "test"
      )
      created_key_id = created_key.fetch(:id)
      assert created_key.fetch(:revealed_key).start_with?("pk_test_"), "Created API key does not start with pk_test_."

      listed_key = find_api_key(client, organization_id, created_key_id)
      refute_nil listed_key, "Created API key should appear in the paginated list."
      assert_equal created_key_id, listed_key.fetch(:id)

      rotated_key = client.organizations.api_keys.rotate(organization_id, created_key_id)
      rotated_key_id = rotated_key.fetch(:id)
      assert rotated_key.fetch(:revealed_key).start_with?("pk_test_"), "Rotated API key does not start with pk_test_."

      fixture = load_fixture("sealed-token/vector.v1.json")
      verified = Foil::Server.safe_verify_foil_token(fixture.fetch(:token), fixture.fetch(:secretKey))
      assert_equal true, verified.fetch(:ok)
      assert_equal fixture.fetch(:payload).fetch(:session_id), verified.fetch(:data).fetch(:session_id)
      assert_equal fixture.fetch(:payload).fetch(:decision).fetch(:event_id), verified.fetch(:data).fetch(:decision).fetch(:event_id)
    ensure
      best_effort_revoke(client, organization_id, rotated_key_id)
      best_effort_revoke(client, organization_id, created_key_id) if created_key_id && created_key_id != rotated_key_id
    end
  end

  private

  def require_env(name)
    ENV.fetch(name)
  rescue KeyError
    raise "#{name} is required for the live smoke suite."
  end

  def env_or_default(name, fallback)
    value = ENV[name]
    value.nil? || value.empty? ? fallback : value
  end

  def find_api_key(client, organization_id, key_id)
    cursor = nil

    loop do
      page = client.organizations.api_keys.list(organization_id, limit: 100, cursor: cursor)
      found = page.items.find { |item| item.fetch(:id) == key_id }
      return found if found
      return nil unless page.has_more && page.next_cursor

      cursor = page.next_cursor
    end
  end

  def best_effort_revoke(client, organization_id, key_id)
    return unless key_id

    client.organizations.api_keys.revoke(organization_id, key_id)
  rescue Foil::Server::ApiError => error
    raise unless error.status == 404 || error.code == "request.not_found"
  end
end
