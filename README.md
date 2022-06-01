# Cognito Playground

## Examples

### API Auth

This demonstrates how a FastAPI application can be authenticated against Cognito. The basic idea is to load Cognito's JWKS and to use that to validate auth tokens.

#### Setup

1. Install requirements:
   ```
   pip install -r requirements.txt
   ```
1. Create user pool in Cognito.
1. Setup environment variables (either in `.env` file or directly in environment):
   - `cognito_user_pool_id` - the user pool's ID

#### Run

```
uvicorn api-auth-example:app --reload
```

### M2M Login

This demonstrates how a service can authenticate with Cognito. The basic idea is to utilize the [Client Credentials](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/) flow.

#### Setup

1. Install requirements:
   ```
   pip install -r requirements.txt
   ```
1. Create user pool in Cognito.
1. In the user pool, create a resource server and custom scope.
1. In the user pool, create an app client with the "client credentials" OAuth 2.0 grant type and the custom scope from the previously created resource server.
1. Setup environment variables (either in `.env` file or directly in environment):
   - `cognito_domain` - the user pool's cognito domain
   - `client_id` - the app client's id
   - `client_secret` - the app client's secret

#### Run

```
./m2m-logon-example.py
```

### Programmatic Login

The represents how a user can authenticate with a Cogntio application within an interactive Python environment (e.g. Python Notebook).

File: `programmatic-login-example.py`

#### Setup

1. Install requirements:
   ```
   pip install -r requirements.txt
   ```
1. Create user pool in Cognito.
1. In the user pool, create an app client without a secret and with the `ALLOW_USER_PASSWORD_AUTH` flow.
1. Create user in user pool.
1. Optionally, setup environment variables (either in `.env` file or directly in environment; if unset, user will be prompted):
   - `username` - user email address or sub
   - `password` - user password
   - `client_id` - cognito app client identifier
   - `app_client_id` - cognito app client identifier

#### Run

```
./programmatic-login-example.py
```
