# Keys for JWE (MCP Server)

Generate a 4096-bit RSA keypair for JWE:

```bash
cd scripts
./generate_keys.sh
```

This produces:

- `keys/mcp-private.pem` (traditional format; keep safe)
- `keys/mcp-private-pkcs8.pem` (**use this in MCP_PRIVATE_KEY_PEM** env)
- `keys/mcp-public.pem` (distribute to agents for encryption)

Rotate keys regularly and distribute the new public key to agents. Store private keys in a secure secret manager.
