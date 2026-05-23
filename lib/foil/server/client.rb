require "cgi"
require "json"
require "net/http"
require "uri"

module Foil
  module Server
    class Client
      DEFAULT_BASE_URL = "https://api.usefoil.com".freeze
      DEFAULT_TIMEOUT = 30
      SDK_CLIENT_HEADER = "foil-server-ruby/0.1.0".freeze

      attr_reader :sessions, :fingerprints, :organizations, :gate, :webhooks, :timeout

      def initialize(secret_key: ENV["FOIL_SECRET_KEY"], base_url: DEFAULT_BASE_URL, timeout: DEFAULT_TIMEOUT, user_agent: nil, transport: nil)
        @secret_key = secret_key
        @base_url = base_url
        @timeout = timeout
        @user_agent = user_agent
        @transport = transport

        @sessions = SessionsResource.new(self)
        @fingerprints = FingerprintsResource.new(self)
        @organizations = OrganizationsResource.new(self)
        @gate = GateResource.new(self)
        @webhooks = WebhooksResource.new(self)
      end

      def request_json(method, path, query: {}, body: nil, expect_content: true, auth: { kind: :secret })
        url = build_url(path, query)
        headers = {
          "Accept" => "application/json",
          "X-Foil-Client" => SDK_CLIENT_HEADER
        }
        headers["User-Agent"] = @user_agent if @user_agent
        headers["Content-Type"] = "application/json" if body
        apply_auth_headers(headers, auth)

        status, response_headers, response_body =
          if @transport
            @transport.call(method: method, url: url.to_s, headers: headers, body: body.nil? ? nil : JSON.dump(body))
          else
            perform_http_request(method, url, headers, body)
          end

        request_id = response_headers["x-request-id"] || response_headers["X-Request-Id"]

        if status >= 400
          payload = parse_json(response_body)
          if payload[:error].is_a?(Hash)
            error = payload[:error]
            details = error[:details].is_a?(Hash) ? error[:details] : {}
            raise ApiError.new(
              status: status,
              code: error[:code] || "request.failed",
              message: error[:message] || response_body.to_s,
              request_id: request_id || error[:request_id],
              field_errors: details[:fields] || [],
              docs_url: error[:docs_url],
              body: payload
            )
          end

          raise ApiError.new(status: status, code: "request.failed", message: response_body.to_s, request_id: request_id, body: payload)
        end

        return {} unless expect_content
        return {} if status == 204 || response_body.nil? || response_body.empty?

        parse_json(response_body)
      end

      def perform_http_request(method, url, headers, body)
        http = Net::HTTP.new(url.host, url.port)
        http.use_ssl = (url.scheme == "https")
        http.read_timeout = @timeout
        http.open_timeout = @timeout

        request_class = case method
        when "GET" then Net::HTTP::Get
        when "POST" then Net::HTTP::Post
        when "PATCH" then Net::HTTP::Patch
        when "DELETE" then Net::HTTP::Delete
        else
          raise ArgumentError, "Unsupported method #{method}"
        end

        request = request_class.new(url)
        headers.each { |key, value| request[key] = value }
        request.body = JSON.dump(body) if body

        response = http.request(request)
        [response.code.to_i, response.to_hash.transform_values { |value| Array(value).first }, response.body.to_s]
      end
      private :perform_http_request

      def build_url(path, query)
        url = URI.join(@base_url.end_with?("/") ? @base_url : "#{@base_url}/", path.sub(%r{\A/}, ""))
        compact_query = query.each_with_object({}) do |(key, value), memo|
          memo[key] = value unless value.nil? || value == ""
        end
        url.query = URI.encode_www_form(compact_query) unless compact_query.empty?
        url
      end
      private :build_url

      def parse_json(body)
        data = JSON.parse(body)
        deep_symbolize(data)
      rescue JSON::ParserError
        {}
      end
      private :parse_json

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
      private :deep_symbolize

      def apply_auth_headers(headers, auth)
        kind = (auth[:kind] || :secret).to_sym
        case kind
        when :none
          headers
        when :bearer
          token = auth[:token]
          raise ConfigurationError, "Missing bearer token for this Foil request." if token.nil? || token.empty?

          headers["Authorization"] = "Bearer #{token}"
        else
          raise ConfigurationError, "Missing Foil secret key. Pass secret_key explicitly or set FOIL_SECRET_KEY." if @secret_key.nil? || @secret_key.empty?

          headers["Authorization"] = "Bearer #{@secret_key}"
        end
      end
      private :apply_auth_headers
    end

    class BaseResource
      def initialize(client)
        @client = client
      end

      private

      def list_result(payload)
        ListResult.new(
          items: payload[:data],
          limit: payload.fetch(:pagination).fetch(:limit),
          has_more: payload.fetch(:pagination).fetch(:has_more),
          next_cursor: payload.fetch(:pagination)[:next_cursor]
        )
      end
    end

    class SessionsResource < BaseResource
      def list(limit: nil, cursor: nil, verdict: nil, search: nil)
        payload = @client.request_json("GET", "/v1/sessions", query: {
          limit: limit,
          cursor: cursor,
          verdict: verdict,
          search: search
        })
        list_result(payload)
      end

      def get(session_id)
        @client.request_json("GET", "/v1/sessions/#{CGI.escape(session_id)}")[:data]
      end

      def attach_client_user(session_id, client_user_id)
        @client.request_json("PATCH", "/v1/sessions/#{CGI.escape(session_id)}", body: {
          client_user_id: client_user_id
        })[:data]
      end

      def clear_client_user(session_id)
        @client.request_json("PATCH", "/v1/sessions/#{CGI.escape(session_id)}", body: {
          client_user_id: nil
        })[:data]
      end

      def iter(limit: nil, verdict: nil, search: nil)
        Enumerator.new do |yielder|
          cursor = nil
          loop do
            page = list(limit: limit, cursor: cursor, verdict: verdict, search: search)
            page.items.each { |item| yielder << item }
            break unless page.has_more && page.next_cursor

            cursor = page.next_cursor
          end
        end
      end
    end

    class FingerprintsResource < BaseResource
      def list(limit: nil, cursor: nil, search: nil, sort: nil)
        payload = @client.request_json("GET", "/v1/fingerprints", query: {
          limit: limit,
          cursor: cursor,
          search: search,
          sort: sort
        })
        list_result(payload)
      end

      def get(visitor_id)
        @client.request_json("GET", "/v1/fingerprints/#{CGI.escape(visitor_id)}")[:data]
      end

      def iter(limit: nil, search: nil, sort: nil)
        Enumerator.new do |yielder|
          cursor = nil
          loop do
            page = list(limit: limit, cursor: cursor, search: search, sort: sort)
            page.items.each { |item| yielder << item }
            break unless page.has_more && page.next_cursor

            cursor = page.next_cursor
          end
        end
      end
    end

    class ApiKeysResource < BaseResource
      def create(organization_id, name:, type: nil, environment: nil, allowed_origins: nil, scopes: nil)
        payload = @client.request_json("POST", "/v1/organizations/#{CGI.escape(organization_id)}/api-keys", body: compact({
          name: name,
          type: type,
          environment: environment,
          allowed_origins: allowed_origins,
          scopes: scopes
        }))
        payload[:data]
      end

      def list(organization_id, limit: nil, cursor: nil)
        payload = @client.request_json("GET", "/v1/organizations/#{CGI.escape(organization_id)}/api-keys", query: {
          limit: limit,
          cursor: cursor
        })
        list_result(payload)
      end

      def update(organization_id, key_id, name: nil, allowed_origins: nil, scopes: nil)
        @client.request_json("PATCH", "/v1/organizations/#{CGI.escape(organization_id)}/api-keys/#{CGI.escape(key_id)}", body: compact({
          name: name,
          allowed_origins: allowed_origins,
          scopes: scopes
        }))[:data]
      end

      def revoke(organization_id, key_id)
        @client.request_json("DELETE", "/v1/organizations/#{CGI.escape(organization_id)}/api-keys/#{CGI.escape(key_id)}")[:data]
      end

      def rotate(organization_id, key_id)
        payload = @client.request_json("POST", "/v1/organizations/#{CGI.escape(organization_id)}/api-keys/#{CGI.escape(key_id)}/rotations")
        payload[:data]
      end

      private

      def compact(hash)
        hash.reject { |_key, value| value.nil? }
      end
    end

    class OrganizationsResource < BaseResource
      attr_reader :api_keys

      def initialize(client)
        super(client)
        @api_keys = ApiKeysResource.new(client)
      end

      def create(name:, slug:)
        @client.request_json("POST", "/v1/organizations", body: { name: name, slug: slug })[:data]
      end

      def get(organization_id)
        @client.request_json("GET", "/v1/organizations/#{CGI.escape(organization_id)}")[:data]
      end

      def update(organization_id, name: nil, status: nil)
        @client.request_json("PATCH", "/v1/organizations/#{CGI.escape(organization_id)}", body: {
          name: name,
          status: status
        }.reject { |_key, value| value.nil? })[:data]
      end
    end

    class GateResource < BaseResource
      attr_reader :registry, :services, :sessions, :login_sessions, :agent_tokens

      def initialize(client)
        super(client)
        @registry = GateRegistryResource.new(client)
        @services = GateServicesResource.new(client)
        @sessions = GateSessionsResource.new(client)
        @login_sessions = GateLoginSessionsResource.new(client)
        @agent_tokens = GateAgentTokensResource.new(client)
      end
    end

    class GateRegistryResource < BaseResource
      def list
        @client.request_json("GET", "/v1/gate/registry", auth: { kind: :none })[:data]
      end

      def get(service_id)
        @client.request_json("GET", "/v1/gate/registry/#{CGI.escape(service_id)}", auth: { kind: :none })[:data]
      end
    end

    class GateServicesResource < BaseResource
      def list
        @client.request_json("GET", "/v1/gate/services")[:data]
      end

      def get(service_id)
        @client.request_json("GET", "/v1/gate/services/#{CGI.escape(service_id)}")[:data]
      end

      def create(id:, name:, description:, website:, webhook_endpoint_id:, discoverable: nil, dashboard_login_url: nil, env_vars: nil, docs_url: nil, sdks: nil, branding: nil, consent: nil)
        @client.request_json("POST", "/v1/gate/services", body: compact({
          id: id,
          discoverable: discoverable,
          name: name,
          description: description,
          website: website,
          dashboard_login_url: dashboard_login_url,
          webhook_endpoint_id: webhook_endpoint_id,
          env_vars: env_vars,
          docs_url: docs_url,
          sdks: sdks,
          branding: branding,
          consent: consent
        }))[:data]
      end

      def update(service_id, discoverable: nil, name: nil, description: nil, website: nil, dashboard_login_url: nil, webhook_endpoint_id: nil, env_vars: nil, docs_url: nil, sdks: nil, branding: nil, consent: nil)
        @client.request_json("PATCH", "/v1/gate/services/#{CGI.escape(service_id)}", body: compact({
          discoverable: discoverable,
          name: name,
          description: description,
          website: website,
          dashboard_login_url: dashboard_login_url,
          webhook_endpoint_id: webhook_endpoint_id,
          env_vars: env_vars,
          docs_url: docs_url,
          sdks: sdks,
          branding: branding,
          consent: consent
        }))[:data]
      end

      def disable(service_id)
        @client.request_json("DELETE", "/v1/gate/services/#{CGI.escape(service_id)}")[:data]
      end

      private

      def compact(hash)
        hash.reject { |_key, value| value.nil? }
      end
    end

    class WebhooksResource < BaseResource
      def list_endpoints(organization_id)
        payload = @client.request_json("GET", "/v1/organizations/#{CGI.escape(organization_id)}/webhooks/endpoints")
        list_result(payload)
      end

      def create_endpoint(organization_id, name:, url:, event_types:)
        @client.request_json("POST", "/v1/organizations/#{CGI.escape(organization_id)}/webhooks/endpoints", body: {
          name: name,
          url: url,
          event_types: event_types
        })[:data]
      end

      def update_endpoint(organization_id, endpoint_id, **updates)
        @client.request_json("PATCH", "/v1/organizations/#{CGI.escape(organization_id)}/webhooks/endpoints/#{CGI.escape(endpoint_id)}", body: updates)[:data]
      end

      def disable_endpoint(organization_id, endpoint_id)
        @client.request_json("DELETE", "/v1/organizations/#{CGI.escape(organization_id)}/webhooks/endpoints/#{CGI.escape(endpoint_id)}")[:data]
      end

      def rotate_secret(organization_id, endpoint_id)
        @client.request_json("POST", "/v1/organizations/#{CGI.escape(organization_id)}/webhooks/endpoints/#{CGI.escape(endpoint_id)}/rotations")[:data]
      end

      def send_test(organization_id, endpoint_id)
        @client.request_json("POST", "/v1/organizations/#{CGI.escape(organization_id)}/webhooks/endpoints/#{CGI.escape(endpoint_id)}/test")[:data]
      end

      def list_events(organization_id, endpoint_id: nil, type: nil, limit: nil)
        payload = @client.request_json("GET", "/v1/organizations/#{CGI.escape(organization_id)}/events", query: {
          endpoint_id: endpoint_id,
          type: type,
          limit: limit
        })
        list_result(payload)
      end

      def retrieve_event(organization_id, event_id)
        @client.request_json("GET", "/v1/organizations/#{CGI.escape(organization_id)}/events/#{CGI.escape(event_id)}")[:data]
      end
    end

    class GateSessionsResource < BaseResource
      def create(service_id:, account_name:, delivery:, metadata: nil)
        body = {
          service_id: service_id,
          account_name: account_name,
          delivery: delivery
        }
        body[:metadata] = metadata unless metadata.nil?

        @client.request_json("POST", "/v1/gate/sessions", body: body, auth: { kind: :none })[:data]
      end

      def poll(gate_session_id, poll_token:)
        @client.request_json(
          "GET",
          "/v1/gate/sessions/#{CGI.escape(gate_session_id)}",
          auth: { kind: :bearer, token: poll_token }
        )[:data]
      end

      def acknowledge(gate_session_id, poll_token:, ack_token:)
        @client.request_json(
          "POST",
          "/v1/gate/sessions/#{CGI.escape(gate_session_id)}/ack",
          body: { ack_token: ack_token },
          auth: { kind: :bearer, token: poll_token }
        )[:data]
      end
    end

    class GateLoginSessionsResource < BaseResource
      def create(service_id:, agent_token:)
        @client.request_json(
          "POST",
          "/v1/gate/login-sessions",
          body: { service_id: service_id },
          auth: { kind: :bearer, token: agent_token }
        )[:data]
      end

      def consume(code:)
        @client.request_json("POST", "/v1/gate/login-sessions/consume", body: { code: code })[:data]
      end
    end

    class GateAgentTokensResource < BaseResource
      def verify(agent_token:)
        @client.request_json("POST", "/v1/gate/agent-tokens/verify", body: { agent_token: agent_token })[:data]
      end

      def revoke(agent_token:)
        @client.request_json(
          "POST",
          "/v1/gate/agent-tokens/revoke",
          body: { agent_token: agent_token },
          expect_content: false
        )
        nil
      end
    end
  end
end
