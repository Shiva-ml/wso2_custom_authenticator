package org.wso2.custom.local.authenticator.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Deactivate;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.wso2.custom.local.authenticator.SampleLocalAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.user.core.service.RealmService;

@Component(
        name = "org.wso2.carbon.custom.local.authenticator",
        immediate = true)
public class SampleLocalAuthenticatorServiceComponent {

    private static Log log = LogFactory.getLog(SampleLocalAuthenticatorServiceComponent.class);

    private static RealmService realmService;

    @Activate
    protected void activate(ComponentContext ctxt) {

        try {
            SampleLocalAuthenticator sampleLocalAuthenticator = new SampleLocalAuthenticator();
            ctxt.getBundleContext().registerService(ApplicationAuthenticator.class.getName(),
                    sampleLocalAuthenticator, null);
            if (log.isDebugEnabled()) {
                log.info("SampleLocalAuthenticator bundle is activated");
            }
        } catch (Throwable e) {
            log.error("SampleLocalAuthenticator bundle activation Failed", e);
        }
    }

    @Deactivate
    protected void deactivate(ComponentContext ctxt) {

        if (log.isDebugEnabled()) {
            log.info("SampleLocalAuthenticator bundle is deactivated");
        }
    }

    public static RealmService getRealmService() {

        return realmService;
    }

    @Reference(name = "realm.service",
            service = org.wso2.carbon.user.core.service.RealmService.class,
            cardinality = ReferenceCardinality.MANDATORY,
            policy = ReferencePolicy.DYNAMIC,
            unbind = "unsetRealmService")
    protected void setRealmService(RealmService realmService) {

        log.debug("Setting the Realm Service");
        SampleLocalAuthenticatorServiceComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {

        log.debug("UnSetting the Realm Service");
        SampleLocalAuthenticatorServiceComponent.realmService = null;
    }
}