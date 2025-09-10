require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { JWE, jwtVerify, createRemoteJWKSet, importPKCS8 } = require('jose');
const fetch = require('node-fetch');

const app = express();

app.use(helmet());
app.use(rateLimit({
  windowMs: 60 * 1000,
  max: 60
}));

// Accept raw JWE bodies
app.use(express.raw({ type: 'application/jose', limit: '64kb' }));

const {
  MCP_PRIVATE_KEY_PEM,
  AGENT_JWT_ISSUER,
  AGENT_JWT_AUDIENCE,
  AGENT_JWT_JWKS_URL,
  AGENT_JWT_HS256_SECRET,
  ANET_API_LOGIN_ID,
  ANET_TRANSACTION_KEY,
  ANET_ENV,
  PORT
} = process.env;

const jwks = AGENT_JWT_JWKS_URL ? createRemoteJWKSet(new URL(AGENT_JWT_JWKS_URL)) : null;

async function verifyAgentJWT(authHeader) {
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    throw new Error('Missing bearer token');
  }
  const token = authHeader.slice(7);
  if (jwks) {
    const { payload } = await jwtVerify(token, jwks, {
      issuer: AGENT_JWT_ISSUER,
      audience: AGENT_JWT_AUDIENCE
    });
    return payload;
  } else if (AGENT_JWT_HS256_SECRET) {
    const secret = new TextEncoder().encode(AGENT_JWT_HS256_SECRET);
    const { payload } = await jwtVerify(token, secret, {
      algorithms: ['HS256'],
      issuer: AGENT_JWT_ISSUER,
      audience: AGENT_JWT_AUDIENCE
    });
    return payload;
  } else {
    throw new Error('No JWT verification method configured');
  }
}

function buildAnetRequest(decrypted) {
  const { card, opaqueData, transaction, customer, merchantReferenceId } = decrypted;
  const { amount, currency, capture } = transaction;
  const req = {
    createTransactionRequest: {
      merchantAuthentication: {
        name: ANET_API_LOGIN_ID,
        transactionKey: ANET_TRANSACTION_KEY
      },
      refId: merchantReferenceId,
      transactionRequest: {
        transactionType: capture === false ? 'authOnlyTransaction' : 'authCaptureTransaction',
        amount,
        currencyCode: currency,
        payment: {}
      }
    }
  };
  if (card) {
    req.createTransactionRequest.transactionRequest.payment.creditCard = {
      cardNumber: card.number,
      expirationDate: `${card.expYear}-${String(card.expMonth).padStart(2, '0')}`,
      cardCode: card.cvv
    };
  } else if (opaqueData) {
    req.createTransactionRequest.transactionRequest.payment.opaqueData = opaqueData;
  }
  if (customer && customer.email) {
    req.createTransactionRequest.transactionRequest.customer = { email: customer.email };
  }
  if (customer && customer.phone) {
    req.createTransactionRequest.transactionRequest.billTo = { phoneNumber: customer.phone };
  }
  return req;
}

function anetEndpoint() {
  return ANET_ENV === 'PRODUCTION'
    ? 'https://api2.authorize.net/xml/v1/request.api'
    : 'https://apitest.authorize.net/xml/v1/request.api';
}

app.post('/anet/transactions/auth', async (req, res) => {
  try {
    await verifyAgentJWT(req.headers['authorization']);
    const privateKey = await importPKCS8(MCP_PRIVATE_KEY_PEM, 'RSA-OAEP-256');
    const { plaintext, protectedHeader } = await JWE.decrypt(req.body, privateKey);
    if (protectedHeader.alg !== 'RSA-OAEP-256' || protectedHeader.enc !== 'A256GCM') {
      throw new Error('Unsupported encryption');
    }
    const decrypted = JSON.parse(new TextDecoder().decode(plaintext));
    const body = buildAnetRequest(decrypted);
    const resp = await fetch(anetEndpoint(), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const result = await resp.json();
    res.status(200).json({ ok: true, anet: result });
  } catch (err) {
    res.status(400).json({ ok: false, error: err.message });
  }
});

app.get('/healthz', (_req, res) => res.json({ ok: true }));

const port = PORT || 8080;
app.listen(port, () => {
  console.log(`Server running on ${port}`);
});
