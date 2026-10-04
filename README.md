# Foil Ruby Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Ruby 3.3+](https://img.shields.io/badge/ruby-3.3%2B-CC342D?logo=ruby&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Foil Ruby library provides convenient access to the Foil API from applications written in Ruby. It includes a client for Sessions, visitor fingerprints, Organizations, Organization API key management, webhook endpoints, and sealed token verification.

The library also provides:

- a fast configuration path using `FOIL_SECRET_KEY`
- lazy helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- webhook endpoint management, test sends, event delivery history, and webhook signature verification

## Documentation

See the [Foil docs](https://usefoil.com/docs) and [API reference](https://usefoil.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the gem. If you just want to use the package, run:

```bash
bundle add foil-server
```

## Requirements

- Ruby 3.3+

## Usage

Use `FOIL_SECRET_KEY` or `secret_key:`:

```ruby
require "foil/server"

client = Foil::Server::Client.new(secret_key: "sk_live_...")

page = client.sessions.list(verdict: "bot", limit: 25)
session = client.sessions.get("sid_0123456789abcdefghjkmnpqrs")
client.sessions.attach_client_user("sid_0123456789abcdefghjkmnpqrs", "user_123")
client.sessions.clear_client_user("sid_0123456789abcdefghjkmnpqrs")

puts "#{session[:decision][:automation_status]} #{session[:highlights].first&.fetch(:summary, nil)}"
```

### Sealed token verification

```ruby
result = Foil::Server.safe_verify_foil_token(sealed_token, "sk_live_...")

if result[:ok]
  puts "#{result[:data][:decision][:verdict]} #{result[:data][:decision][:risk_score]}"
else
  warn result[:error].message
end
```

### Pagination

```ruby
client.sessions.iter(search: "signup").each do |session|
  puts "#{session[:id]} #{session[:latest_decision][:verdict]}"
end
```

### Visitor fingerprints

```ruby
fingerprint = client.fingerprints.get("vid_0123456789abcdefghjkmnpqrs")
puts fingerprint[:id]
```

### Organizations

```ruby
organization = client.organizations.get("org_0123456789abcdefghjkmnpqrs")
updated = client.organizations.update("org_0123456789abcdefghjkmnpqrs", name: "New Name")

puts updated[:name]
```

### Organization API keys

```ruby
created = client.organizations.api_keys.create("org_0123456789abcdefghjkmnpqrs", name: "Production", type: "secret", environment: "live")
client.organizations.api_keys.revoke("org_0123456789abcdefghjkmnpqrs", created[:id])
```

### Webhooks

```ruby
endpoint = client.webhooks.create_endpoint(
  "org_0123456789abcdefghjkmnpqrs",
  name: "Production alerts",
  url: "https://example.com/foil/webhook",
  event_types: ["session.result.persisted"]
)

events = client.webhooks.list_events(
  "org_0123456789abcdefghjkmnpqrs",
  endpoint_id: endpoint[:id],
  type: "session.result.persisted"
)

puts events.items.first[:webhook_deliveries].first[:status]
```

#### Verifying webhook deliveries

Every webhook delivery is signed with your endpoint's signing secret. Verify the `X-Foil-Timestamp` and `X-Foil-Signature` headers against the raw request body before trusting the payload:

```ruby
valid = Foil::Server.verify_webhook_signature(
  secret: ENV.fetch("FOIL_WEBHOOK_SECRET"),
  timestamp: request.headers["X-Foil-Timestamp"],
  raw_body: raw_body,
  signature: request.headers["X-Foil-Signature"]
)

# Verify and parse in one step. Raises ArgumentError if the signature is invalid or expired.
event = Foil::Server.verify_and_parse_webhook_event(
  secret: ENV.fetch("FOIL_WEBHOOK_SECRET"),
  timestamp: request.headers["X-Foil-Timestamp"],
  raw_body: raw_body,
  signature: request.headers["X-Foil-Signature"]
)

puts event[:data] if event[:type] == "session.result.persisted"

# Parse a payload you have already verified.
parsed = Foil::Server.parse_webhook_event(raw_body)
```

Signatures older than five minutes are rejected by default. Pass `max_age_seconds:` to change the tolerance.

### Error handling

```ruby
begin
  client.sessions.list(limit: 999)
rescue Foil::Server::ApiError => error
  warn "#{error.status} #{error.code} #{error.message}"
end
```

## Support

If you need help integrating Foil, start with [usefoil.com/docs](https://usefoil.com/docs).
