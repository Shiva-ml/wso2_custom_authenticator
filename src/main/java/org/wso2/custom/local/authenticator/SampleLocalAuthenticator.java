package org.wso2.custom.local.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.LocalApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.identity.base.IdentityRuntimeException;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.core.UniqueIDUserStoreManager;
import org.wso2.carbon.user.core.UserCoreConstants;
import org.wso2.carbon.user.core.common.AuthenticationResult;
import org.wso2.custom.local.authenticator.internal.SampleLocalAuthenticatorServiceComponent;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;

import java.net.URL;
import java.net.HttpURLConnection;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Scanner;

import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.*;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorParamMetadata;
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import org.wso2.carbon.user.api.Claim;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreManager;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;


/**
 * This is the sample local authenticator which will be used to authenticate the user based on the registered mobile
 * phone number.
 */
public class SampleLocalAuthenticator extends AbstractApplicationAuthenticator implements
        LocalApplicationAuthenticator {

    private static final Log log = LogFactory.getLog(SampleLocalAuthenticator.class);
    private static final String MOBILE_CLAIM_URL = "http://wso2.org/claims/telephone";
    private static final String USERNAME = "username";
    private static final String PASSWORD = "password";
    private static final String PASSCODE = "passcode";
    private static final String DISPLAY_PASSCODE = "passcode";

    private static final String USERNAME_PARAM = "username";
    private static final String PIN_PARAM = "pin_number";
    public static final String PASSWORD_PARAM = "password";
    public static final String DISPLAY_PIN = "PIN";
    private static final String AUTHENTICATOR_MESSAGE = "AuthenticatorMessage";
    private static final String DISPLAY_USER_NAME = "username";

    @Override
    public boolean canHandle(HttpServletRequest httpServletRequest) {

        String userName = httpServletRequest.getParameter(USERNAME);
        String passcode = httpServletRequest.getParameter(PASSCODE);
        return userName != null && passcode != null;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        String loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        // This is the default WSO2 IS login page. If you can create your custom login page you can use that instead.
        String queryParams =
                FrameworkUtils.getQueryStringWithFrameworkContextId(context.getQueryParams(),
                        context.getCallerSessionKey(),
                        context.getContextIdentifier());

        try {
            String retryParam = "";

            if (context.isRetrying()) {
                retryParam = "&authFailure=true&authFailureMsg=login.fail.message";
            }

            response.sendRedirect(response.encodeRedirectURL(loginPage + ("?" + queryParams)) +
                    "&authenticators=BasicAuthenticator:" + "LOCAL" + retryParam);
        } catch (IOException e) {
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest httpServletRequest,
                                                 HttpServletResponse httpServletResponse,
                                                 AuthenticationContext authenticationContext)
            throws AuthenticationFailedException {

        String username = httpServletRequest.getParameter(USERNAME);
        String passcode = httpServletRequest.getParameter(PASSCODE);

        if (username==null || username.isEmpty() || passcode.isEmpty() || passcode.isEmpty() ){
            throw new AuthenticationFailedException("ABA-60001",
                    "Invalid authentication request");

        }

        String accountLockedValue = userStoreManager.getUserClaimValue(tenantAwareUsername,
                "http://wso2.org/claims/accountLocked", null);
        log.info

        boolean isAuthenticated = false;

        // Call external API for authentication
        try {
            URL url = new URL("http://localhost:8081/users/verify-creds");
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Content-Type", "application/json");
            connection.setDoOutput(true);

            // Build the JSON payload
            String payload = "{\"username\":\"" + username + "\", \"passcode\":\"" + passcode + "\"}";

            try (OutputStream os = connection.getOutputStream()) {
                os.write(payload.getBytes(StandardCharsets.UTF_8));
                os.flush();
            }

            int responseCode = connection.getResponseCode();
            if (responseCode == 200) {
                isAuthenticated = true;
                // Authentication successful: set the authenticated user
                AuthenticatedUser authenticatedUser =
                        AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username);
                authenticationContext.setSubject(authenticatedUser);


            } else {
                log.error("External authentication API returned response code: " + responseCode);
                authenticationContext.setProperty("AuthErrorCode", "401");
                authenticationContext.setProperty("AuthErrorMessage", "wrong credentials");
                authenticationContext.setProperty("AuthErrorDescription", "provide correct passcode");
                //authenticationContext.setProperty("authenticatorMessage"," wrong credentials");



            }
        } catch (Exception e) {
            log.error("Error while calling external authentication API", e);
            authenticationContext.setProperty("AuthErrorCode", "500");
            authenticationContext.setProperty("AuthErrorMessage", "internal server error");
            authenticationContext.setProperty("AuthErrorDescription", "Failed to validate passcode");
            authenticationContext.setProperty("AuthErrorCause", e.getMessage());
            //throw new AuthenticationFailedException("Error calling external authentication API: " + e.getMessage(), e);
            throw new AuthenticationFailedException("ABA-65001",
                    "Unable to proceed with authentication.");
        }

        // If authentication fails, throw an exception
       if (!isAuthenticated) {
            if (log.isDebugEnabled()) {
                log.debug("User authentication failed due to invalid credentials");
            }

            throw new InvalidCredentialsException("User authentication failed due to invalid credentials",
                    User.getUserFromUserName(username));
        }

        // Set the authenticated user in the context (redundant if already set above)
        authenticationContext.setSubject(AuthenticatedUser.createLocalAuthenticatedUserFromSubjectIdentifier(username));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest httpServletRequest) {

        return httpServletRequest.getParameter("sessionDataKey");
    }

    @Override
    public String getName() {

        return "SampleLocalAuthenticator";
    }

    @Override
    public String getFriendlyName() {

        return "sample-local-authenticator";
    }

    public boolean isAPIBasedAuthenticationSupported() {
        return true;
    }


    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        String idpName = null;
        if (context != null && context.getExternalIdP() != null) {
            idpName = context.getExternalIdP().getIdPName();
        }

        AuthenticatorData authenticatorData = new AuthenticatorData();
        if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            AuthenticatorMessage authenticatorMessage = (AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE);
            authenticatorData.setMessage(authenticatorMessage);
        }

        authenticatorData.setName(getName());
        authenticatorData.setI18nKey(getI18nKey());
        authenticatorData.setIdp(idpName);
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.USER_PROMPT);
        setAuthParams(authenticatorData);

        List<String> requiredParams = new ArrayList<>();
        requiredParams.add(USERNAME);
        requiredParams.add(PASSCODE);
        authenticatorData.setRequiredParams(requiredParams);

        return Optional.of(authenticatorData);
    }

    private static void setAuthParams(AuthenticatorData authenticatorData) {

        List<AuthenticatorParamMetadata> authenticatorParamMetadataList = new ArrayList<>();
        AuthenticatorParamMetadata usernameMetadata = new AuthenticatorParamMetadata(
                USERNAME, DISPLAY_USER_NAME, FrameworkConstants.AuthenticatorParamType.STRING,
                0, Boolean.FALSE, USERNAME_PARAM);
        authenticatorParamMetadataList.add(usernameMetadata);
        AuthenticatorParamMetadata passwordMetadata = new AuthenticatorParamMetadata(
                PASSCODE, DISPLAY_PASSCODE, FrameworkConstants.AuthenticatorParamType.STRING,
                1, Boolean.TRUE, PASSCODE);
        authenticatorParamMetadataList.add(passwordMetadata);
        authenticatorData.setAuthParams(authenticatorParamMetadataList);
    }



    private boolean isAccountLocked(String username) throws AuthenticationFailedException {
        try {
            // Get tenant-aware username (in case of multi-tenancy)
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);

            // Get RealmService
            RealmService realmService = SampleLocalAuthenticatorServiceComponent.getRealmService();
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);

            // Get User Realm
            UserRealm userRealm = realmService.getTenantUserRealm(tenantId);
            if (userRealm != null) {
                UserStoreManager userStoreManager = userRealm.getUserStoreManager();

                // Retrieve the accountLocked claim
                String accountLockedValue = userStoreManager.getUserClaimValue(tenantAwareUsername,
                        "http://wso2.org/claims/accountLocked", null);

                return Boolean.parseBoolean(accountLockedValue);
            } else {
                throw new AuthenticationFailedException("User Realm is null for tenant: " + tenantDomain);
            }
        } catch (Exception e) {
            throw new AuthenticationFailedException("Error while checking account lock status", e);
        }
    }



}