# MCP Server for Authorize.Net with Message-Level Encryption (MLE)

This package contains an **enterprise-ready MCP server** (Node.js/Express) that accepts **JWE-encrypted** payloads from agents,
decrypts inside the container, validates, and relays to **Authorize.Net CreateTransactionRequest** over TLS.
It also includes a minimal agent sample that encrypts and posts a request.

## Components
- `server/` – MCP server (Express + `jose`) with:
  - Agent authentication (JWT via JWKS or HS256 shared secret)
  - JWE decryption (RSA-OAEP-256 + A256GCM)
  - Strict payload validation (minimal, extend as needed)
  - Callout to Authorize.Net sandbox/production
  - Security hardening (helmet, rate limit, scrubbed logs)
  - Dockerfile for containerized deploy (ToolHive-friendly)

- `agent/` – Sample agent that:
  - Encrypts the payload using the MCP's public key (SPKI PEM)
  - Sends `application/jose` to the MCP endpoint with Bearer JWT

- `keys/` – Instructions for generating RSA keypair for JWE.

- `scripts/` – Helper to generate keys with OpenSSL.

## Quick Start (Local)
1. Generate keys
   ```bash
   cd scripts
   ./generate_keys.sh
   ```
   This writes `keys/mcp-private-pkcs8.pem` and `keys/mcp-public.pem`.

2. Configure server env (copy `.env.example` and set values):
   ```bash
   cd server
   cp .env.example .env
   # edit .env
   ```

3. Install & run server:
   ```bash
   npm ci
   npm start
   ```

4. Run agent sample (in another terminal):
   ```bash
   cd agent
   cp .env.example .env
   npm ci
   node encrypt-and-send.js
   ```

## ToolHive / Container Deploy
- Build the image from `server/Dockerfile` and inject secrets via your orchestrator/ToolHive.
- Only expose `443` behind an ingress/WAF. Prefer mTLS for agent→MCP.
- Set `ANET_ENV=SANDBOX` for testing; switch to `PRODUCTION` when ready.
- Rotate RSA and API keys regularly. NEVER bake secrets into images.

## PCI Notes
If you can, **avoid raw PAN** touching the MCP by using Authorize.Net tokenization (`opaqueData/Accept.js`) on the agent side
and only sending opaque tokens inside the JWE. This drastically reduces PCI scope. This reference implementation shows the
full PAN path strictly for demonstration and enterprise review.

## Architecture Diagram

```text
+-----------+     JWE + JWT     +-----------------------------+     JSON over TLS     +-----------------------+
| Agent     | ----------------> |         MCP Server         | --------------------> |  Authorize.Net API     |
| (Client)  |                  |  (Decrypt JWE, verify JWT, |                      |  (CreateTransaction,    |
|           | <---------------- |    build request, call API) | <------------------  |   CIM, ARB, etc.)       |
+-----------+     Response      +-----------------------------+     Response          +-----------------------+
```
