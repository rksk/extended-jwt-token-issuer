package org.wso2.jwt.custom.claim.filter.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="org.wso2.jwt.custom.claim.filter"
 * immediate="true"
 * @scr.reference name="user.realmservice.default"
 * interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService" unbind="unsetRealmService"
 */
public class AccessTokenClaimFilterComponent {

    private static Log log = LogFactory.getLog(AccessTokenClaimFilterComponent.class);
    private static RealmService realmService;

    protected void activate(ComponentContext ctxt) {

        try {
            log.info("Custom JWT Access token builder activated successfully.");
        } catch (Exception e) {
            log.error("Failed to activate Custom JWT Access token builder", e);
        }
    }

    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.debug("Custom JWT Access token builder is deactivated ");
        }
    }

    protected void setRealmService(RealmService realmService) {

        AccessTokenClaimFilterComponent.realmService = realmService;
        if (log.isDebugEnabled()) {
            log.debug("RealmService is set in the Custom JWT Access token builder bundle");
        }
    }

    protected void unsetRealmService(RealmService realmService) {

        AccessTokenClaimFilterComponent.realmService = null;
        if (log.isDebugEnabled()) {
            log.debug("RealmService is unset in the Custom JWT Access token builder bundle");
        }
    }

    public static RealmService getRealmService() {

        return AccessTokenClaimFilterComponent.realmService;
    }

}
