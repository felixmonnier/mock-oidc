const express = require('express');
const bodyParser = require('body-parser');
const jose = require('node-jose');
const { v4: uuidv4 } = require('uuid');
const cors = require('cors');

const app = express();

// Read configuration from environment variables or fallback to defaults
const port = process.env.PORT || 3000;
const issuer = process.env.OIDC_ISSUER || `http://localhost:${port}`;
const clientConfig = {
    clientId: process.env.OIDC_CLIENT_ID || 'my-client',
    clientSecret: process.env.OIDC_CLIENT_SECRET || 'my-secret',
    redirectUri: process.env.OIDC_DEFAULT_REDIRECT_URI || 'http://localhost:4200/api/auth/callback', // Can be overridden by client
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cors());

// Healthz Endpoint
app.get('/healthz', (req, res) => {
    res.status(200).send('ok');
});

// In-memory store for authorization codes
const authCodes = new Map();

let keyStore = jose.JWK.createKeyStore();
let jwks;

// Generate a key pair for signing JWTs
keyStore.generate('RSA', 2048, { alg: 'RS256', use: 'sig' }).then(key => {
    jwks = keyStore.toJSON();
    console.log('Generated JWKS:', JSON.stringify(jwks, null, 2));
});

// OIDC Discovery Endpoint
app.get('/.well-known/openid-configuration', (req, res) => {
    res.json({
        issuer: issuer,
        authorization_endpoint: `${issuer}/authorize`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: `${issuer}/jwks`,
        scopes_supported: ['openid', 'profile', 'email'],
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
    });
});

// JWKS Endpoint
app.get('/jwks', (req, res) => {
    res.json(jwks);
});

// Authorization Endpoint
app.get('/authorize', (req, res) => {
    const {
        client_id,
        redirect_uri,
        scope,
        state,
        response_type
    } = req.query;

    if (client_id !== clientConfig.clientId) {
        return res.status(400).send('Invalid client_id');
    }
    if (response_type !== 'code') {
        return res.status(400).send('Unsupported response_type');
    }

    const form = `
        <!DOCTYPE html>
        <html>
        <head>
            <title>Mock OIDC Login</title>
            <style>
                body { font-family: sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
                form { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
                h2 { text-align: center; color: #333; }
                label { display: block; margin-bottom: 0.5rem; color: #555; }
                input { width: 100%; padding: 0.5rem; margin-bottom: 1rem; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
                button { width: 100%; padding: 0.75rem; background-color: #007bff; color: white; border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; }
                button:hover { background-color: #0056b3; }
            </style>
        </head>
        <body>
            <form action="/login" method="post">
                <h2>Mock OIDC Login</h2>
                <input type="hidden" name="client_id" value="${client_id}">
                <input type="hidden" name="redirect_uri" value="${redirect_uri}">
                <input type="hidden" name="scope" value="${scope}">
                <input type="hidden" name="state" value="${state}">
                <label for="sub">User ID (sub):</label>
                <input type="text" id="sub" name="sub" value="user123" required>
                <label for="firstName">First Name:</label>
                <input type="text" id="firstName" name="firstName" value="John" required>
                <label for="lastName">Last Name:</label>
                <input type="text" id="lastName" name="lastName" value="Doe" required>
                <label for="email">Email:</label>
                <input type="email" id="email" name="email" value="john.doe@example.com" required>
                <label for="picture">Picture URL:</label>
                <input type="text" id="picture" name="picture" value="https://example.com/avatar.jpg">
                <label for="departmentCodes">Department Codes (comma-separated):</label>
                <input type="text" id="departmentCodes" name="departmentCodes" value="D01,D02">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
    `;
    res.send(form);
});

// Form submission endpoint
app.post('/login', (req, res) => {
    const {
        client_id,
        redirect_uri,
        state,
        scope,
        sub,
        firstName,
        lastName,
        email,
        picture,
        departmentCodes
    } = req.body;

    const code = uuidv4();
    const claims = {
        sub,
        firstName,
        lastName,
        email,
        picture,
        departmentCodes: departmentCodes ? departmentCodes.split(',').map(s => s.trim()) : []
    };

    authCodes.set(code, { claims, clientId: client_id, redirectUri: redirect_uri, scope });

    // Code expires in 1 minute
    setTimeout(() => authCodes.delete(code), 60 * 1000);

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (state) {
        redirectUrl.searchParams.set('state', state);
    }
    res.redirect(redirectUrl.toString());
});

// Token Endpoint
app.post('/token', async (req, res) => {
    let {
        grant_type,
        code,
        redirect_uri,
        client_id,
        client_secret
    } = req.body;

    if (grant_type !== 'authorization_code') {
        return res.status(400).json({ error: 'unsupported_grant_type' });
    }

    const authHeader = req.headers.authorization;
    if (authHeader) {
        const parts = authHeader.split(' ');
        if (parts.length === 2 && parts[0] === 'Basic') {
            const decoded = Buffer.from(parts[1], 'base64').toString('utf8');
            const [id, secret] = decoded.split(':');
            client_id = id;
            client_secret = secret;
        }
    }

    if (client_id !== clientConfig.clientId || client_secret !== clientConfig.clientSecret) {
        console.error('Client authentication failed:', { client_id, expected: clientConfig.clientId });
        return res.status(401).json({ error: 'invalid_client' });
    }

    const authCodeData = authCodes.get(code);
    if (!authCodeData) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Authorization code not found or expired' });
    }

    if (authCodeData.redirectUri !== redirect_uri) {
        return res.status(400).json({ error: 'invalid_grant', error_description: 'Redirect URI mismatch' });
    }

    authCodes.delete(code); // Code can only be used once

    const now = Math.floor(Date.now() / 1000);
    const payload = {
        iss: issuer,
        aud: client_id,
        sub: authCodeData.claims.sub,
        exp: now + 3600, // Expires in 1 hour
        iat: now,
        ...authCodeData.claims
    };

    const key = keyStore.get(jwks.keys[0].kid);
    const idToken = await jose.JWS.createSign({ format: 'compact' }, key)
        .update(JSON.stringify(payload))
        .final();

    res.json({
        access_token: uuidv4(), // Dummy access token
        token_type: 'Bearer',
        expires_in: 3600,
        id_token: idToken,
    });
});


app.listen(port, () => {
    console.log(`Mock OIDC provider listening at ${issuer}`);
});
