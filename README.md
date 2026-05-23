# Foil Ruby Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Ruby 3.3+](https://img.shields.io/badge/ruby-3.3%2B-CC342D?logo=ruby&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Foil Ruby library provides convenient access to the Foil API from applications written in Ruby. It includes a client for Sessions, visitor fingerprints, Organizations, Organization API key management, sealed token verification, Gate, and Gate delivery/webhook helpers.

The library also provides:

- a fast configuration path using `FOIL_SECRET_KEY`
- lazy helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- webhook endpoint management, test sends, and event delivery history
- public, bearer-token, and secret-key auth modes for Gate flows
- Gate delivery/webhook helpers

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

Use `FOIL_SECRET_KEY` or `secret_key:` for core detect APIs. For public or bearer-auth Gate flows, the client can also be created without a secret key:

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
  event_types: ["session.result.persisted", "gate.session.approved"]
)

events = client.webhooks.list_events(
  "org_0123456789abcdefghjkmnpqrs",
  endpoint_id: endpoint[:id],
  type: "session.result.persisted"
)

puts events.items.first[:webhook_deliveries].first[:status]
```

### Gate APIs

```ruby
delivery_key_pair = Foil::Server::GateDelivery.create_delivery_key_pair

services = client.gate.registry.list
session = client.gate.sessions.create(
  service_id: "foil",
  account_name: "my-project",
  delivery: delivery_key_pair[:delivery]
)

puts "#{services.first[:id]} #{session[:consent_url]}"
```

### Gate delivery and webhook helpers

```ruby
key_pair = Foil::Server::GateDelivery.create_delivery_key_pair
response = Foil::Server::GateDelivery.create_gate_approved_webhook_response(
  delivery: key_pair[:delivery],
  outputs: {
    "FOIL_PUBLISHABLE_KEY" => "pk_live_...",
    "FOIL_SECRET_KEY" => "sk_live_..."
  }
)
payload = Foil::Server::GateDelivery.decrypt_gate_delivery_envelope(key_pair[:private_key], response[:encrypted_delivery])

puts payload[:outputs]["FOIL_SECRET_KEY"]
```

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
