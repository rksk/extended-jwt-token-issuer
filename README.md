# extended-self-contained-token-issuer

The JWT self-contained access token and the ID token will contain the same set of claims by default. This is a custom, JWT self-contained token issuer, which can be used to filter out all the user claims from the JWT access token in WSO2 Identity Server.

### Steps to configure
1. Build the project using `mvn clean install`.
2. Copy the jar file from `target` directory to the <IS_HOME>/repository/components/dropins directory.
3. Add the configuration below in the deployment.toml file resides in <IS_HOME>/repository/conf directory.
```
[[oauth.extensions.token_types]]
name = "JWT"
issuer = "org.wso2.custom.identity.oauth2.token.ExtendedJWTTokenIssuer"
persist_access_token_alias = true
```
4. Start/ Restart the server.
5. Create an OAuth service provider in the WSO2 IS. Refer [Configuring OAuth2-OpenID Connect Single-Sign-On](https://is.docs.wso2.com/en/5.10.0/learn/configuring-oauth2-openid-connect-single-sign-on/) documentation to creating an OAuth service provider.
6. The Token Issuer should be set to **JWT**. 
7. Generate an access tome. Refer [OAuth 2.0 Grant Types](https://is.docs.wso2.com/en/5.10.0/learn/oauth-2.0-grant-types/) documentation to try out the OAuth2 grant types.
