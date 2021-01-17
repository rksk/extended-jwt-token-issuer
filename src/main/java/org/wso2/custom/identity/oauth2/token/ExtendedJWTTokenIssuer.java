package org.wso2.custom.identity.oauth2.token;

import com.nimbusds.jwt.JWTClaimsSet;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.token.JWTTokenIssuer;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;

/**
 * Extended JWT Access Token Builder to avoid adding user claims to self-contained access token.
 */
public class ExtendedJWTTokenIssuer extends JWTTokenIssuer {

    private static final Log log = LogFactory.getLog(ExtendedJWTTokenIssuer.class);

    public ExtendedJWTTokenIssuer() throws IdentityOAuth2Exception {
        super();
        if (log.isDebugEnabled()) {
            log.debug("Extended JWT Access token builder is initiated.");
        }
    }

    @Override
    protected JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthAuthzReqMessageContext authzReqMessageContext)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Skipped adding user claims in the extended JWT Access token builder.");
        }
        return jwtClaimsSetBuilder.build();
    }

    @Override
    protected JWTClaimsSet handleCustomClaims(JWTClaimsSet.Builder jwtClaimsSetBuilder,
                                              OAuthTokenReqMessageContext tokenReqMessageContext)
            throws IdentityOAuth2Exception {

        if (log.isDebugEnabled()) {
            log.debug("Skipped adding user claims in the extended JWT Access token builder.");
        }
        return jwtClaimsSetBuilder.build();
    }

}
