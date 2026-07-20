# Sealed Token Specification

Foil sealed tokens are encrypted server handoff payloads returned by `Foil.getSession()`.

This document is the language-agnostic contract for verifying those tokens in public server SDKs.

## Overview

- Input: a base64-encoded sealed token string
- Output: a JSON payload describing the verified Foil session decision for the current action
- Confidentiality and integrity: AES-256-GCM
- Compression: zlib deflate/inflate

## Payload format

After base64 decoding, the byte layout is:

- `version` - 1 byte
- `nonce` - 12 bytes
- `ciphertext` - variable length
- `tag` - 16 bytes

Supported versions:

- `0x01` - legacy single-recipient token
- `0x02` - multi-recipient envelope used for independently issued and rotating secret keys

Version `0x02` uses this byte layout:

- `version` - 1 byte (`0x02`)
- `recipient_count` - unsigned 16-bit big-endian integer, 1 through 256
- `payload_nonce` - 12 bytes
- `payload_ciphertext_length` - unsigned 32-bit big-endian integer
- `payload_ciphertext` - zlib-compressed JSON encrypted with a random 32-byte content key
- `payload_tag` - 16 bytes
- one fixed-size recipient entry per recipient:
  - `recipient_id` - `sha256(normalized_secret + "\\0sealed-results-recipient-id")`; this domain-separated identifier must never expose `normalized_secret`
  - `wrap_nonce` - 12 bytes
  - `wrapped_content_key` - 32 bytes
  - `wrap_tag` - 16 bytes

The payload cipher authenticates `foil-sealed-results-v2\\0payload\\0 + header + ordered_recipient_ids` as AAD, binding the complete recipient set to the payload.
Each content-key wrapper uses the existing derived token key and authenticates
`foil-sealed-results-v2\\0recipient\\0 + recipient_id` as AAD. Verifiers must
retain `0x01` support and reject all other versions.

## Secret normalization

The verifier accepts either:

- a plaintext Foil secret key, such as `sk_live_...`
- or the corresponding lowercase SHA-256 hex digest

Normalization rules:

- If the supplied secret matches `/^[0-9a-f]{64}$/i`, treat it as the secret hash and lowercase it
- Otherwise compute the SHA-256 hex digest of the supplied secret key

## Key derivation

Derive the AES key as:

- `sha256(normalized_secret + "\0sealed-results")`

Use the raw 32-byte digest as the AES-256-GCM key.

## Verification steps

1. Base64 decode the token
2. Parse the version byte, nonce, ciphertext, and tag
3. Normalize the caller's secret material
4. Derive the AES-256-GCM key
5. Decrypt using:
   - algorithm: `aes-256-gcm`
   - nonce: parsed 12-byte nonce
   - tag: parsed 16-byte authentication tag
6. Inflate the decrypted bytes with zlib
7. Parse the inflated UTF-8 JSON payload

Any failure in decoding, parsing, authentication, decompression, or JSON parsing must be treated as verification failure.

## Payload shape

The decrypted JSON payload currently includes:

- `object`
- `session_id`
- `decision`
- `request`
- `visitor_fingerprint`
- `signals`
- `score_breakdown`
- `attribution`
- `embed`

The payload is aligned to the same public vocabulary as the Sessions API:

- `decision`
  - `event_id`
  - `verdict`
  - `risk_score`
  - `phase`
  - `is_provisional`
  - `manipulation`
  - `evaluation_duration_ms`
  - `evaluated_at`
- `request`
  - `url`
  - `user_agent`
  - `ip_address`
  - `screen_size`
  - `is_touch_capable`
- `visitor_fingerprint`
  - `object`
  - `id`
  - `confidence`
  - `identified_at`
- `score_breakdown`
  - `categories`
- `attribution`
  - `bot`

Public SDKs should treat the payload as forward-compatible:

- preserve unknown fields
- do not require fields beyond the documented stable surface

## Fixtures

Golden vectors live under `fixtures/sealed-token/`.

Every language SDK must verify the shared vectors successfully and reject the invalid vectors it ships with.
