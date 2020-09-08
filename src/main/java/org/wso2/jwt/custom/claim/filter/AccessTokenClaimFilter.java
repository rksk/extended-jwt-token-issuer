package org.wso2.jwt.custom.claim.filter;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTClaimsSet.Builder;
import com.nimbusds.jwt.PlainJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.model.RequestParameter;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

import java.util.Arrays;

/**
 * Custom JWT Access Token Builder to filter self-contained access token claims.
 */
public class AccessTokenClaimFilter extends JWTTokenIssuer {

    private static final String CLAIM_FILTER_PARAMETER = "access_token_claims";
    private static final String AUDIENCE = "aud";
    private static final String JTI = "jti";
    private static final String SUB = "sub";
    private Algorithm signatureAlgorithm = null;
    private static final Log log = LogFactory.getLog(AccessTokenClaimFilter.class);

    public AccessTokenClaimFilter() throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Custom JWT Access token builder is initiated.");
        }
        OAuthServerConfiguration config = OAuthServerConfiguration.getInstance();
        // Map signature algorithm from identity.xml to nimbus format, this is a one time configuration.
        signatureAlgorithm = mapSignatureAlgorithm(config.getSignatureAlgorithm());
    }

    @Override
    protected String buildJWTToken(OAuthTokenReqMessageContext request) throws IdentityOAuth2Exception {

        // Set claims to jwt token.
        if (log.isDebugEnabled()) {
            log.debug("Building JWT Access token.");
        }
        JWTClaimsSet jwtClaimsSet = createJWTClaimSet(null, request, request.getOauth2AccessTokenReqDTO()
                .getClientId());
        JWTClaimsSet.Builder jwtClaimsSetBuilder = new JWTClaimsSet.Builder(jwtClaimsSet);

        if (request.getScope() != null && Arrays.asList((request.getScope())).contains(AUDIENCE)) {
            if (log.isDebugEnabled()) {
                log.debug("Adding audience value.");
            }
            jwtClaimsSetBuilder.audience(Arrays.asList(request.getScope()));
        }

        jwtClaimsSet = jwtClaimsSetBuilder.build();
        if (log.isDebugEnabled()) {
            log.debug("JWT claims set for the default JWT Access token is built.");
        }

        jwtClaimsSet = filterClaims(jwtClaimsSet, request);
        if (JWSAlgorithm.NONE.getName().equals(signatureAlgorithm.getName())) {
            return new PlainJWT(jwtClaimsSet).serialize();
        }

        return signJWT(jwtClaimsSet, request, null);
    }

    private JWTClaimsSet filterClaims(JWTClaimsSet jwtClaimsSet, OAuthTokenReqMessageContext tokenReqMessageContext) {

        if (log.isDebugEnabled()) {
            log.debug("Filtering claims from the JWT Access token.");
        }
        Builder filteredJWTClaimsSetBuilder = new Builder();
        String[] filterClaims = getFilterClaims(tokenReqMessageContext);

        if (isFilterClaimsProvided(filterClaims)) {
            if (log.isDebugEnabled()) {
                log.debug("Filter claims provided: " + Arrays.asList(filterClaims));
            }

            for (String filterClaim : filterClaims) {
                if (log.isDebugEnabled()) {
                    log.debug("Adding the claim: " + filterClaim);
                }
                filteredJWTClaimsSetBuilder.claim(filterClaim, jwtClaimsSet.getClaim(filterClaim));
            }
            setDefaultClaims(filteredJWTClaimsSetBuilder, jwtClaimsSet);

            return filteredJWTClaimsSetBuilder.build();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Filter claims are not provided. Hence complete JWT token will be returned.");
            }
            return jwtClaimsSet;
        }
    }

    private String[] getFilterClaims(OAuthTokenReqMessageContext tokenReqMessageContext) {

        String[] filterClaims = null;
        RequestParameter[] requestParameters =
                tokenReqMessageContext.getOauth2AccessTokenReqDTO().getRequestParameters();
        for (RequestParameter requestParameter : requestParameters) {
            if (requestParameter.getKey().equals(CLAIM_FILTER_PARAMETER)) {
                filterClaims = requestParameter.getValue();
            }
        }

        if (ArrayUtils.isNotEmpty(filterClaims)) {
            filterClaims = filterClaims[0].trim().split(" ");
        }

        return filterClaims;
    }

    private boolean isFilterClaimsProvided(String[] filterClaims) {

        return ArrayUtils.isNotEmpty(filterClaims) && StringUtils.isNotEmpty(filterClaims[0]);
    }

    private void setDefaultClaims(Builder filteredJWTClaimsSetBuilder, JWTClaimsSet jwtClaimsSet) {

        if (log.isDebugEnabled()) {
            log.debug("Adding default claims.");
        }
        filteredJWTClaimsSetBuilder.claim(JTI, jwtClaimsSet.getJWTID());
        filteredJWTClaimsSetBuilder.claim(SUB, jwtClaimsSet.getSubject());
    }
}
