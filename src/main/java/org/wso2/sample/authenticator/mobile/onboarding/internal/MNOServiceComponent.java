package org.wso2.sample.authenticator.mobile.onboarding.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.*;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.event.services.IdentityEventService;
import org.wso2.carbon.identity.governance.IdentityGovernanceService;
import org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.sample.authenticator.mobile.onboarding.MobileNumberOnboardingAuthenticator;

import java.util.Hashtable;

@Component(
        name = "org.wso2.sample.authenticator.mobile.onboarding.component",
        immediate = true
)
public class MNOServiceComponent {

    private static final Log log = LogFactory.getLog(MNOServiceComponent.class);
    private static RealmService realmService;
    private static IdentityEventService eventService;
    private  static IdentityGovernanceService identityGovernanceService;
    private static AccountLockService accountLockService;

    @Activate
    protected void activate(ComponentContext ctxt) {
        try {
            MobileNumberOnboardingAuthenticator mnoAuthenticator = new MobileNumberOnboardingAuthenticator();
            Hashtable<String, String> props = new Hashtable<String, String>();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(), mnoAuthenticator, props);
            log.info("MobileNumberOnboardingAuthenticator bundle is activated.");
        } catch (Throwable e) {
            log.error("MobileNumberOnboardingAuthenticator bundle activation failed.", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.info("MobileNumberOnboardingAuthenticator bundle is deactivated.");
        }
    }

    @Reference(
            name = "EventMgtService",
            service = org.wso2.carbon.identity.event.services.IdentityEventService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityEventService"
    )
    protected void setIdentityEventService(IdentityEventService eventService) {
        MNOServiceComponent.eventService = eventService;
    }

    protected void unsetIdentityEventService(IdentityEventService eventService) {
        MNOServiceComponent.eventService = null;
    }

    @Reference(
            name = "IdentityGovernanceService",
            service = org.wso2.carbon.identity.governance.IdentityGovernanceService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetIdentityGovernanceService"
    )
    protected void setIdentityGovernanceService(IdentityGovernanceService idpManager) {

        MNOServiceComponent.identityGovernanceService = idpManager;
    }

    protected void unsetIdentityGovernanceService(IdentityGovernanceService idpManager) {

        MNOServiceComponent.identityGovernanceService = null;
    }

    @Reference(
            name = "AccountLockService",
            service = org.wso2.carbon.identity.handler.event.account.lock.service.AccountLockService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetAccountLockService"
    )
    protected void setAccountLockService(AccountLockService accountLockService) {

        MNOServiceComponent.accountLockService = accountLockService;
    }

    protected void unsetAccountLockService(AccountLockService accountLockService) {

        MNOServiceComponent.accountLockService = null;
    }

    public static IdentityEventService getIdentityEventService() {
        return eventService;
    }

    public static IdentityGovernanceService getIdentityGovernanceService() {
        return identityGovernanceService;
    }

    public static AccountLockService getAccountLockService() {
        return accountLockService;
    }
}
