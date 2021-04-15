/**
 *
 * Performs post-processing for failed and succeeded authentication attempts.
 *
 * @author mk@eggs.de
 * @author sb@eggs.de
 * @author Debasis.Mishra
 */

package com.shell.b2b.cq.uam.authhandler;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;

import javax.jcr.Credentials;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.api.security.authentication.token.TokenCredentials;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.jcr.api.SlingRepository;
import org.osgi.framework.Constants;
import org.osgi.framework.ServiceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ibm.icu.util.ULocale;
import com.shell.b2b.cq.common.sessionhandler.ShellSessionHandler;
import com.shell.b2b.cq.uam.entities.User;
import com.shell.b2b.cq.uam.entities.UserStatusCode;
import com.shell.b2b.cq.uam.exception.LDAPBaseException;
import com.shell.b2b.cq.uam.exception.LDAPGetUserAccountStatusException;
import com.shell.b2b.cq.uam.exception.LDAPGetUserGroupsException;
import com.shell.b2b.cq.uam.exception.NGAPFindUserByUserNameException;
import com.shell.b2b.cq.uam.exception.NGAPSetUserStatusCodeException;
import com.shell.b2b.cq.uam.services.LDAPAccessor;
import com.shell.b2b.cq.uam.services.NGAPAccessor;
import com.shell.b2b.cq.uam.services.impl.ngaputils.NGAPResult;
import com.shell.cq.common.bean.NGUserProfile;
import com.shell.cq.common.bean.TermsAndConditionSelector;
import com.unboundid.ldap.sdk.LDAPException;

//@Component(metatype = true, label = "NGMH CQ (CONFIG): ShellAuthenticationHandler")
//@Properties({
//        @Property(name = Constants.SERVICE_DESCRIPTION, value = "Shell Authentication Handler"),
//        @Property(name = Constants.SERVICE_VENDOR, value = "Logica"),
//        @Property(name = Constants.SERVICE_PID, value = "com.shell.b2b.cq.uam.authhandler.ShellAuthenticationHandler"),
//        @Property(name = AuthenticationHandler.PATH_PROPERTY, value = "/", propertyPrivate = false, label = "Path", description = "Repository path for which this authentication handler should be used by Sling. If this is empty, the authentication handler will be disabled."),
//        @Property(name = AuthenticationHandler.TYPE_PROPERTY, value = "TOKEN", propertyPrivate = true),
//        @Property(name = Constants.SERVICE_RANKING, intValue = 10000, propertyPrivate = false, label = "Service Ranking", description = "OSGi Framework Service Ranking value to indicate the order in which to call this service. This is an int value where higher values designate higher precendence. The default value is 10000."),
//        @Property(name = "token.required.attr", value = "ip", propertyPrivate = false, label = "Required Attributes", description = "Which request properties to use as required attributes for authentication. Possible values are \"ip\" (client IP addess), \"agent\" (HTTP User-Agent request header), \"ip_agent\" (both) and \"none\". The default value is \"ip\"."),
//        @Property(name = "token.alternate.url", value = "", propertyPrivate = false, label = "Alternate Authentication URL", description = "Alternate URL for the user name and password submission by the form. This name is can be used in addition to the 'j_security_check' to avoid any conflict with the application server's security. The default value is empty.") })
//@Service
public class ShellAuthenticationHandler extends TokenAuthenticationHandler {/*
    private static final Logger LOG = LoggerFactory.getLogger(ShellAuthenticationHandler.class);

    private static final String CREDENTIALS = "user.jcr.credentials";

    private static final String DESCRIPTION = "Shell Token Authentication Handler";

    private static final String LOGOUT_URL_PATH = "/apps/utils/logout";

    private static final String REFERER = "referer";

    private static final String CHARSET = "UTF-8";

    private static final String PAR_J_REASON = "j_reason";

    private static final String J_REASON_DEACTIVATED = "Account is deactivated, please contact help desk";

    private static final String J_REASON_LOCKED = "Account is temporarily locked, please try again later";

    private static final String J_REASON_INACTIVE = "Password is expired, please contact help desk";

    @Property(value = { "admin" }, cardinality = 100, propertyPrivate = false, label = "Whitelisted User Names", description = "Array of user names to be excluded from UAM-specific processing. The default value is \"admin\".")
    private static final String KEY_USER_NAME_WHITELIST = "user.name.whitelist";
    
    @Reference
    private LDAPAccessor ldapAccessor;

    @Reference
    private NGAPAccessor ngapAccessor;

    private TermsAndConditionSelector termsAndConditionsSelector;

    private HashSet<String> userNameWhitelist = null;

    @Reference
    private SlingRepository repository;

    @Override
    public String toString() {
        return DESCRIPTION;
    }

    @Override
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response,
            AuthenticationInfo authInfo) {
        if (authInfo == null) {
            // Nothing to do
            if (LOG.isTraceEnabled()) {
                LOG.trace("[AuthenticationInfo] object is null");
            }
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        if (LOG.isTraceEnabled()) {
            LOG.trace("[AuthenticationInfo] authentication type was [{}]", authInfo.getAuthType());
        }

        // Extract credentials from authentication information
        Credentials credentials = (Credentials) authInfo.get(CREDENTIALS);
        if (credentials == null) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Authentication failed, but the [AuthenticationInfo] object has no key [{}]", CREDENTIALS);
            }
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        // Check if credentials are simple credentials
        if (!(credentials instanceof SimpleCredentials)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Authentication failed, but the [AuthenticationInfo] object's key [{}] does not contain a [SimpleCredentials] object", CREDENTIALS);
            }
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        // Get user name from simple credentials
        String userName = ((SimpleCredentials) credentials).getUserID();

        if (StringUtils.isBlank(userName)) {
            if (LOG.isTraceEnabled()) {
                LOG.trace("Authentication failed, but the [SimpleCredentials] object retrieved with the [AuthenticationInfo] object's key [{}] does not contain a user name", CREDENTIALS);
            }
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Authentication failed for user name [{}]", userName);
        }

        // Check if user name is whitelisted
        if (userNameWhitelist.contains(userName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("[{}] is a whitelisted user name, skipping user status code processing", userName);
            }
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        // Get user object
        NGAPResult<User> userResult = null;
        try {
            userResult = ngapAccessor.findUserProfile(userName);
        } catch (NGAPFindUserByUserNameException e) {
            // Cannot handle exceptions here
        	LOG.error(e.getMessage(),e);
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        User[] userArray = userResult.getResultArray();

        // There must be exactly ONE result
        if (userArray.length != 1) {
            if (LOG.isErrorEnabled()) {
                LOG.error("NGAP returned [{}] results for user name [{}]", userArray.length, userName);
            }
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        User user = userArray[0];

        // Get user status code from NGAP
        UserStatusCode ngapUserStatusCode = user.getUserStatusCode();

        // Get user status code from LDAP
        UserStatusCode ldapUserStatusCode;
        try {
            ldapUserStatusCode = ldapAccessor.getUserAccountStatus(userName);
        } catch (LDAPGetUserAccountStatusException e) {
            // Cannot handle exceptions here
        	LOG.error(e.getMessage(),e);
            super.authenticationFailed(request, response, authInfo);
            return;
        }

        if (ngapUserStatusCode != ldapUserStatusCode
                && ngapUserStatusCode.isTransitionValid(ldapUserStatusCode)) {
            // Synchronize user status code with NGAP
            if (LOG.isDebugEnabled()) {
                LOG.debug("Setting NGAP user status code for user name [{}] to [{}]", userName, ldapUserStatusCode.getStatusCode());
            }

            try {
                ngapAccessor.setUserStatusCode(userName, ldapUserStatusCode, userName);
            } catch (NGAPSetUserStatusCodeException e) {
                // Cannot handle exceptions here
            	LOG.error(e.getMessage(),e);
                super.authenticationFailed(request, response, authInfo);
                return;
            }
        }

        // Provide a meaningful failure reason if available
        switch (ldapUserStatusCode) {
        case DEACTIVATED:
            request.setAttribute(PAR_J_REASON, J_REASON_DEACTIVATED);
            break;
        case LOCKED:
            request.setAttribute(PAR_J_REASON, J_REASON_LOCKED);
            break;
        case INACTIVE:
            request.setAttribute(PAR_J_REASON, J_REASON_INACTIVE);
            break;
        default:
            request.setAttribute(PAR_J_REASON, null);
        }

        super.authenticationFailed(request, response, authInfo);
    }

    private void logoutAndRedirectToLogin(HttpServletRequest request, HttpServletResponse response,
            String logoutReason) {
        try {
            StringBuffer redirectURL = new StringBuffer(LOGOUT_URL_PATH);

            String referer = request.getHeader(REFERER);
            if (StringUtils.isNotEmpty(referer)) {
                // Remove protocol, hostname and port from request so that only the path and the query string of the referrer url are left
                referer = referer.replaceAll("^.*://([^/?#]*)", "");

                redirectURL.append("?resource=");
                redirectURL.append(referer);
                redirectURL.append("&j_reason=");
                redirectURL.append(URLEncoder.encode(logoutReason, CHARSET));
            }

            response.sendRedirect(redirectURL.toString());
        } catch (IOException e) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Failed to send logout redirect", e);
            }
        }
    }

    @Override
    public boolean authenticationSucceeded(HttpServletRequest request,
            HttpServletResponse response, AuthenticationInfo authInfo) {
        LOG.debug("In authenticationSucceeded START");
        NGUserProfile userProfile = null;
        Object object = null;
        
        if (ShellSessionHandler.getInstance().isSessionValid(request)){
        	object = ShellSessionHandler.getInstance().getUserSession(request).get(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE);
        } else {
        	ShellSessionHandler.getInstance().createSession(request, response);
        }
        
        //TODO DELETE START HERE
        //Object object_old = request.getSession(true).getAttribute(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE);
        //TODO DELETE END HERE
        if (object instanceof NGUserProfile) {
        	//TODO DELETE START HERE
			//userProfile = (NGUserProfile) request.getSession(false).getAttribute(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE);
        	//TODO DELETE END HERE
        	userProfile = (NGUserProfile) ShellSessionHandler.getInstance().getUserSession(request).get(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE);
			LOG.debug("@@@@ SHARAD : USER PROFILE STORED FROM PREVIOUS SESSION : \n"+userProfile.toString());
		}
		LOG.debug("ShellAuthenticationHandler : REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));

        LOG.debug("User from session in ShellAuthenticationHandler " + userProfile);

        if (userProfile != null) {
        	LOG.debug("ShellAuthenticationHandler : PREVIOUS SESSION RESTORED THEREFORE CALLING super.authenticationSucceeded() : \n"+userProfile.toString());
        	LOG.debug("ShellAuthenticationHandler 1 : REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));
			return super.authenticationSucceeded(request, response, authInfo);
		} else {
			LOG.debug("ShellAuthenticationHandler : USER PROFILE NOT PRESENT IN BROWSER :: super.authenticationSucceeded();");
		}

        LOG.debug(" authinfo " + authInfo);
        if (authInfo == null) {
            // Nothing to do
            if (LOG.isTraceEnabled()) {
                LOG.trace("[AuthenticationInfo] object is null");
            }
            LOG.debug("ShellAuthenticationHandler 2 : REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));
            return super.authenticationSucceeded(request, response, authInfo);
        }

        // Extract credentials from authentication information
        Credentials credentials = (Credentials) authInfo.get(CREDENTIALS);
        String userName = null;
        if (credentials == null) {
            LOG.debug("credentials in ShellAuthenticationHandler is null");
            if (LOG.isTraceEnabled()) {
                LOG.trace("Authentication succeeded, but the [AuthenticationInfo] object has no key [{}]", CREDENTIALS);
            }
            LOG.debug("ShellAuthenticationHandler 3 : REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));
            return super.authenticationSucceeded(request, response, authInfo);
        } else if (credentials instanceof SimpleCredentials) {
            // Check if credentials are simple credentials
            LOG.debug("credentials in ShellAuthenticationHandler is SimpleCredentials");
            userName = ((SimpleCredentials) credentials).getUserID();
        } else if (credentials instanceof TokenCredentials) {
            LOG.debug("credentials in ShellAuthenticationHandler is TokenCredentials");
            Object obj = request.getAttribute("org.apache.sling.auth.core.ResourceResolver");
            if ((obj instanceof ResourceResolver)) {
                userName = ((ResourceResolver) obj).getUserID();
            }
        }
        // Get user name from simple credentials
        if (StringUtils.isBlank(userName)) {
            LOG.debug("StringUtils.isBlank(userName) is true");
            if (LOG.isTraceEnabled()) {
                LOG.trace("Authentication succeeded, but the [SimpleCredentials] object retrieved with the [AuthenticationInfo] object's key [{}] does not contain a user name", CREDENTIALS);
            }
            LOG.debug("ShellAuthenticationHandler 4 : REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));
            return super.authenticationSucceeded(request, response, authInfo);
        }

        LOG.debug("Authentication succeeded for user name [{}]", userName);

        // Check if user name is whitelisted
        if (userNameWhitelist.contains(userName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("[{}] is a whitelisted user name, skipping user profile processing", userName);
            }
            LOG.debug("ShellAuthenticationHandler : REGISTERING DUMMY SESSION BASED ON PREVIOUS CODE BASE.");
            registerDummyUserProfile(request, userName);
            return super.authenticationSucceeded(request, response, authInfo);
        }

        // Get user object
        NGAPResult<User> userResult = null;
        try {
            LOG.debug("invoking ngapAccessor.findUserProfile for ", userName);
            userResult = ngapAccessor.findUserProfile(userName);
        } catch (NGAPFindUserByUserNameException e) {
            LOG.error("error while ngapAccessor.findUserProfile for " + userName, e);
            // Cannot handle exceptions here
            logoutAndRedirectToLogin(request, response, "Could not load user data from NGAP");

            return super.authenticationSucceeded(request, response, authInfo);
        }

        User[] userArray = userResult.getResultArray();

        if (userArray.length != 1) {
            // There must be exactly ONE result
            if (LOG.isErrorEnabled()) {
                LOG.error("NGAP returned [{}] results for user name [{}]", userArray.length, userName);
            }

            logoutAndRedirectToLogin(request, response, "User data missing in NGAP");

            return super.authenticationSucceeded(request, response, authInfo);
        }

        User user = userArray[0];

        // Double-check that the user is active
        UserStatusCode ngapUserStatusCode = user.getUserStatusCode();
        LOG.debug("User status code for  [{}] is [{}]", userName, ngapUserStatusCode);
        if (ngapUserStatusCode != UserStatusCode.ACTIVE) {
            if (ngapUserStatusCode.isTransitionValid(UserStatusCode.ACTIVE)) {
                
                 *  The user authentication was successful even though the user status code in NGAP
                 *  is not set to active. This may occur when LDAP temporarily locks or expires the
                 *  user account and the user unsuccessfully tries to log on which in turn causes
                 *  the user status code in NGAP to be synchronized with LDAP. Since LDAP not just automatically locks but also unlocks user accounts, this particular user status
                 *  code change now once again needs to be synchronized with NGAP.
                 
                ngapUserStatusCode = UserStatusCode.ACTIVE;
                user.setUserStatusCode(ngapUserStatusCode);

                try {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("Setting NGAP user status code for user name [{}] to [{}]", userName, ngapUserStatusCode.getStatusCode());
                    }

                    ngapAccessor.setUserStatusCode(userName, ngapUserStatusCode, userName);
                } catch (NGAPSetUserStatusCodeException e) {
                    // Cannot handle exceptions here
                	LOG.error(e.getMessage(),e);
                    return super.authenticationSucceeded(request, response, authInfo);
                }
            } else {
                // The user authentication was successful even though the user status code in NGAP
                // does not allow the user to log on.
                if (LOG.isErrorEnabled()) {
                    LOG.error("Denying access since the user status code for user name [{}] is [{}] in NGAP", userName, ngapUserStatusCode);
                }

                logoutAndRedirectToLogin(request, response, "User deactivated in NGAP");

                return super.authenticationSucceeded(request, response, authInfo);
            }
        }
        LOG.debug("ShellAuthenticationHandler : Getting user info from LDAP");
        HashSet<String> userExperienceGroups = null;
        try {
            userExperienceGroups = ldapAccessor.getUserExperienceGroups(userName);
        } catch (LDAPGetUserGroupsException e) {
            LOG.error("Could not load experience groups from LDAP", e);
            logoutAndRedirectToLogin(request, response, "Could not load experience groups from LDAP");

            return super.authenticationSucceeded(request, response, authInfo);
        }

        HashSet<String> userSiteGroups = null;
        try {
            userSiteGroups = ldapAccessor.getUserSiteGroups(userName);
        } catch (LDAPGetUserGroupsException e) {
            LOG.error("Could not load site groups from LDAP", e);
            logoutAndRedirectToLogin(request, response, "Could not load site groups from LDAP");

            return super.authenticationSucceeded(request, response, authInfo);
        }

        HashSet<String> userFunctionalGroups = null;
        try {
            userFunctionalGroups = ldapAccessor.getUserFunctionalGroups(userName);
        } catch (LDAPGetUserGroupsException e) {
            LOG.error("Could not load functional groups from LDAP", e);
            logoutAndRedirectToLogin(request, response, "Could not load functional groups from LDAP");

            return super.authenticationSucceeded(request, response, authInfo);
        }

        HashSet<String> userCustomerGroups = null;
        try {
            userCustomerGroups = ldapAccessor.getUserCustomerGroups(userName);
        } catch (LDAPGetUserGroupsException e) {
            LOG.error("Could not load user customer groups from LDAP", e);
            logoutAndRedirectToLogin(request, response, "Could not load user customer groups from LDAP");

            return super.authenticationSucceeded(request, response, authInfo);
        }

        String languageCode = user.getLanguageCode();
        if (StringUtils.isBlank(languageCode)) {
            // Get language code from browser
            languageCode = ULocale.acceptLanguage(request.getHeader("Accept-Language"), null).getLanguage();
            user.setLanguageCode(languageCode);
        }

        String countryCode = user.getCountryCode();
        if (StringUtils.isBlank(countryCode)) {
            // Get country code from browser
            countryCode = ULocale.acceptLanguage(request.getHeader("Accept-Language"), null).getCountry();
            user.setCountryCode(countryCode);
        }

        ULocale locale = new ULocale(languageCode, countryCode);

        // Create user profile
        userProfile = new NGUserProfile();
        try {
            ldapAccessor.getAllUserAttributes(userName, userProfile);
        } catch (LDAPBaseException e1) {
            LOG.error("Error in getting All the UserAttributes", e1);

        } catch (LDAPException e1) {
            LOG.error("Error in getting All the UserAttributes", e1);

        }
        userProfile.setUser(user);
        Locale uLocale = new Locale(userProfile.getDefaultLanguage(), userProfile.getOU());
        userProfile.setExperienceGroups(userExperienceGroups);
        userProfile.setSiteGroups(userSiteGroups);
        userProfile.setFunctionalGroups(userFunctionalGroups);
        userProfile.setCustomerGroups(userCustomerGroups);
        userProfile.setLocale(locale);
        userProfile.setUserLocale(uLocale);

        Object obj = request.getAttribute("org.apache.sling.auth.core.ResourceResolver");
        if ((obj instanceof ResourceResolver)) {
            ResourceResolver resourceResolver = ((ResourceResolver) obj);
            Session jcrSession = resourceResolver.adaptTo(Session.class);
            termsAndConditionsSelector = new TermsAndConditionSelector(jcrSession);
            String latestTermsAndConditions = termsAndConditionsSelector.getTermsAndConditionsVersion(userProfile);
            boolean tocAcceptanceIsUpToDate = latestTermsAndConditions.equals(user.getTocVersion());
            userProfile.setTocAcceptanceIsUpToDate(tocAcceptanceIsUpToDate);
        }
        // Store user and customer objects in session
        
        // TODO REFACTOR : DELETE START HERE
        HttpSession session = request.getSession(true);
        session.setAttribute(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE, userProfile);
        // TODO REFACTOR : DELETE END HERE
        
        ShellSessionHandler.getInstance().getUserSession(request).put(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE, userProfile);
        LOG.debug("USER : "+userProfile.getUser().getUserName()+" :: SHELL SESSION ID : "+ShellSessionHandler.getInstance().getShellSessionId(request));

        LOG.debug("ShellAuthenticationHandler FINAL EXIT : SHELL SESSION ID = "+ShellSessionHandler.getInstance().getShellSessionId(request)+" :: ========USER PROFILE CREATED===== \n " + userProfile);
        return super.authenticationSucceeded(request, response, authInfo);
    }

    *//**
     * Register a dummy profile for users which are whitelisted
     *//*
    private void registerDummyUserProfile(HttpServletRequest request, String userName) {
        NGUserProfile userProfile;
        User dummyUser = new User();
        dummyUser.setUserName(userName);
        dummyUser.setFirstName(userName);
        dummyUser.setLastName(userName);

        userProfile = new NGUserProfile();
        userProfile.setUser(dummyUser);
        userProfile.setTocAcceptanceIsUpToDate(true);

        // Store user and customer objects in session
        HttpSession session = request.getSession(true);
        session.setAttribute(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE, userProfile);
    }

    @Override
    @Activate
    protected void activate(Map<String, Object> configuration) {
        if (configuration == null) {
            if (LOG.isErrorEnabled()) {
                LOG.error("Configuration is [null]");
            }
            throw new ServiceException("Configuration is [null]");
        }

        // Initialize user name whitelist
        userNameWhitelist = new HashSet<String>();
        if (configuration.get(KEY_USER_NAME_WHITELIST) instanceof String) {
            userNameWhitelist.add((String) configuration.get(KEY_USER_NAME_WHITELIST));
        } else if (configuration.get(KEY_USER_NAME_WHITELIST) instanceof String[]) {
            for (String userName : (String[]) configuration.get(KEY_USER_NAME_WHITELIST)) {
                userNameWhitelist.add(userName);
            }
        }
        
        super.activate(configuration);
    }
*/}
