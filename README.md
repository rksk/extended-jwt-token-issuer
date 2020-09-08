# self-contained-token-claim-filter

The JWT self-contained access token and the ID token will contain the same set of claims by default. This is a custom, JWT self-contained token issuer, which can be used to filter the claims to be included in the access token in WSO2 Identity Server.

The claims to be filtered are provided as a POST parameter: **access_token_claims**, seperated by space in a similar way we provide the scopes.
```
'access_token_claims=given_name family_name'
```
### Steps to configure
1. Build the project using `mvn clean install` and get the jar file.
2. Copy the jar file to the <IS_HOME>/repository/components/dropins directory.
3. Add the configuration below in the deployment.toml file resides in <IS_HOME>/repository/conf directory.
```
[oauth.extensions]
token_generator="org.wso2.jwt.custom.claim.filter.AccessTokenClaimFilter"
```
4. Start/ Restart the server.
5. Create an OAuth service provider in the WSO2 IS. Refer [Configuring OAuth2-OpenID Connect Single-Sign-On](https://is.docs.wso2.com/en/5.10.0/learn/configuring-oauth2-openid-connect-single-sign-on/) documentation to creating an OAuth service provider.
6. Please note that the Token Issuer should be set to **Default** to use the custom JWT token issuer. 
7. Invoke the token endpoint providing the claims to be filtered. A sample request is provided below.
```
curl --location --request POST 'https://localhost:9443/oauth2/token' \
--header 'Authorization: Basic b05vU2IxaHRwd0QwaWFhcERTSmRfaWlHQkh3YTpCaWJRZTdYMWJNVWVzamVBOWxCNVpCcTVYa2dh' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=password' \
--data-urlencode 'username=admin' \
--data-urlencode 'password=admin' \
--data-urlencode 'scope=openid' \
--data-urlencode 'access_token_claims=given_name family_name'
```
8. Refer [OAuth 2.0 Grant Types](https://is.docs.wso2.com/en/5.10.0/learn/oauth-2.0-grant-types/) documentation to try out the OAuth2 grant types.
