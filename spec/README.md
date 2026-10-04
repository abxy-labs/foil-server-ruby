# Server SDK Spec

This directory is the authoritative cross-language contract for Foil server SDKs.

It defines:

- the supported server API surface
- the shared sealed token verification behavior
- golden fixtures for success, error, pagination, and helper flows

## Scope

Server SDKs include only customer-facing APIs:

- `/v1/sessions`
- `/v1/fingerprints`
- `/v1/organizations`
- `/v1/organizations/:organizationId/api-keys`

Server SDKs do **not** include:

- collect endpoints
- internal scoring APIs
- dashboard/internal APIs
- framework adapters
- retry middleware
- policy helpers like `shouldBlock`

## Required Namespaces

Every server SDK should expose these top-level capabilities:

- Sessions
  - list
  - get
  - iterator / auto-pagination helper
- Fingerprints
  - list
  - get
  - iterator / auto-pagination helper
- Organizations
  - create
  - get
  - update
- Organization API keys
  - create
  - list
  - revoke
  - rotate
- sealed token helpers
  - strict verify
  - safe verify

## Shared Defaults

Every SDK should default to:

- `base_url = https://api.usefoil.com`
- `secret_key = env(FOIL_SECRET_KEY)`
- request timeout support
- no automatic retries

## Pagination Normalization

List APIs should normalize cursor pagination into these fields using each language's native style:

- `items`
- `limit`
- `has_more`
- `next_cursor`

The underlying API responses remain cursor-based. SDKs may expose helper iterators/enumerators/page walkers on top.

## Error Model

SDKs should parse API failures into structured errors with, at minimum:

- `status`
- `code`
- `message`
- `request_id`
- `field_errors`
- `docs_url`
- parsed raw body

Use the fixtures in `fixtures/errors/` as the source of truth for error-shape behavior.

## Sealed Token Verification

`sealed-token.md` is the cross-language source of truth for verification behavior.

SDKs must implement verification natively in their own language runtime. They should not depend on another SDK implementation.

Use both:

- `fixtures/sealed-token/vector.v1.json`
- `fixtures/sealed-token/invalid.json`

to validate correctness and failure behavior.

## Sync Model

This repo is the source of truth for the shared server SDK contract.

Each language SDK repo carries a synced copy of this repository in `spec/`, and the Foil monorepo vendors this repository as a submodule at `sdk-spec/server`.

Keep the synced copies and the monorepo submodule pointer current before advancing them.

## SDK Authoring Checklist

When changing any server SDK:

- sync `spec/` before changing SDK code or tests
- do not expose collect or internal-only endpoints
- preserve the shared defaults:
  - env-based secret key fallback
  - `https://api.usefoil.com`
  - request timeout support
  - no automatic retries
- preserve pagination normalization:
  - `items`
  - `limit`
  - `has_more`
  - `next_cursor`
- preserve structured API errors
- keep sealed token golden-vector coverage
- keep one live smoke suite per SDK
- only update the vendored SDK `spec/` copies or the monorepo submodule pointer after the relevant CI is green
