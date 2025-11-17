# Mock OIDC Provider

This is a minimalist Node.js Express application that mocks an OpenID Connect (OIDC) provider.

It supports the authorization code flow and provides `openid` and `profile` scopes.

## Features

- OIDC Discovery endpoint (`.well-known/openid-configuration`)
- JWKS endpoint (`/jwks`) for token verification keys
- Authorization endpoint (`/authorize`) with a login form
- Token endpoint (`/token`) to exchange an authorization code for an `id_token`

## Installation

1.  Clone the repository.
2.  Install the dependencies:
    ```bash
    npm install
    ```

## Running the application

To start the mock OIDC provider, run:

```bash
npm start
```

The server will start on `http://localhost:3000`.

## Configuration

The mock provider uses the following default configuration in `index.js`:

-   **Issuer:** `http://localhost:3000`
-   **Client ID:** `my-client`
-   **Client Secret:** `my-secret`
-   **Default Redirect URI:** `http://localhost:8080/auth/callback`

The client application connecting to this provider should be configured with these values. The redirect URI can be passed as a parameter in the authorization request.

## How it works

1.  A client application starts the OIDC flow by redirecting the user to the `/authorize` endpoint.
2.  The user is presented with a login form where they can enter their details (or use the pre-filled values).
3.  Upon submission, the server generates an authorization code and redirects the user back to the client's `redirect_uri`.
4.  The client then makes a POST request to the `/token` endpoint with the authorization code.
5.  The server validates the code and returns a signed `id_token` (JWT) containing the user's claims.
