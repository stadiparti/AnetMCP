import 'dotenv/config';
import { JWE, importSPKI } from 'jose';
import fetch from 'node-fetch';

const MCP_PUBLIC_KEY_PEM = process.env.MCP_PUBLIC_KEY_PEM;
const MCP_URL = process.env.MCP_URL || 'https://localhost:8080/payments/charge';
const AGENT_JWT = process.env.AGENT_JWT;

if (!MCP_PUBLIC_KEY_PEM || !AGENT_JWT) {
  console.error('Missing MCP_PUBLIC_KEY_PEM or AGENT_JWT');
  process.exit(1);
}

// Sample payload (NEVER log real data)
const payload = {
  card: { number: '4111111111111111', expMonth: '12', expYear: '2028', cvv: '123' },
  customer: { email: 'alice@example.com', phone: '+14255551234' },
  transaction: { amount: '19.99', currency: 'USD', capture: true },
  merchantReferenceId: 'ORDER-100045'
};

async function main() {
  const publicKey = await importSPKI(MCP_PUBLIC_KEY_PEM, 'RSA-OAEP-256');
  const plaintext = new TextEncoder().encode(JSON.stringify(payload));

  const jwe = await new JWE.Encrypt(plaintext)
    .setProtectedHeader({ alg: 'RSA-OAEP-256', enc: 'A256GCM' })
    .encrypt(publicKey);

  const resp = await fetch(MCP_URL, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/jose',
      'Authorization': `Bearer ${AGENT_JWT}`
    },
    body: jwe
  });

  const out = await resp.json();
  console.log(JSON.stringify(out, null, 2));
}

main().catch(e => {
  console.error(e);
  process.exit(1);
});
