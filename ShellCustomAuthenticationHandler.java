package com.shell.b2b.cq.uam.authhandler;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.jcr.Credentials;
import javax.jcr.Session;
import javax.jcr.SimpleCredentials;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.Activate;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.ConfigurationPolicy;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.PropertyUnbounded;
import org.apache.felix.scr.annotations.Reference;
import org.apache.felix.scr.annotations.ReferenceCardinality;
import org.apache.felix.scr.annotations.ReferencePolicy;
import org.apache.felix.scr.annotations.Service;
import org.apache.jackrabbit.api.security.authentication.token.TokenCredentials;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.AuthUtil;
import org.apache.sling.auth.core.spi.AbstractAuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.auth.core.spi.DefaultAuthenticationFeedbackHandler;
import org.apache.sling.commons.osgi.OsgiUtil;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.apache.sling.jcr.api.SlingRepository;
import org.apache.sling.settings.SlingSettingsService;
import org.osgi.framework.Constants;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.day.crx.security.token.TokenCookie;
import com.shell.b2b.cq.common.sessionhandler.ShellSessionHandler;
import com.shell.b2b.cq.common.targetting.UserTargetting;
import com.shell.b2b.cq.common.targetting.UserTargettingImpl;
import com.shell.b2b.cq.uam.akamai.ShellCookie;
import com.shell.b2b.cq.uam.business.services.StationaryDataService;
import com.shell.b2b.cq.uam.business.services.UserService;
import com.shell.b2b.cq.uam.entities.User;
import com.shell.b2b.cq.uam.exception.LDAPBaseException;
import com.shell.b2b.cq.uam.exception.LDAPGetUserGroupsException;
import com.shell.b2b.cq.uam.exception.NGAPBaseException;
import com.shell.b2b.cq.uam.services.LDAPAccessor;
import com.shell.b2b.cq.uam.services.NGAPAccessor;
import com.shell.b2b.cq.uam.utils.CommonUtil;
import com.shell.b2b.cq.uam.utils.HandlerUtil;
import com.shell.cq.common.bean.NGUserProfile;
import com.shell.cq.common.bean.SiteProfile;
import com.shell.cq.common.bean.TermsAndConditionSelector;
import com.shell.cq.common.bean.UserTypeCode;
import com.shell.cq.common.constants.GlobalConstants;
import com.shell.cq.common.utils.MultisiteUtils;
import com.shell.cq.dex.services.TransactConfigurationService;
import com.unboundid.ldap.sdk.LDAPException;

@SuppressWarnings("deprecation")
@Component(metatype = true, immediate = true, label = "NGMH CQ (CONFIG): ShellCustomAuthenticationHandler", description = "ShellCustomAuthenticationHandler", policy = ConfigurationPolicy.REQUIRE)
@Service
@Properties({
        @Property(name = "service.description", value = { "SHELL Custom Authentication Handler" }, propertyPrivate = true),
        @Property(name = "service.vendor", value = { "WIPRO" }, propertyPrivate = true),
        @Property(name = Constants.SERVICE_PID, value = "com.shell.b2b.cq.uam.authhandler.ShellCustomAuthenticationHandler"),
        @Property(name = AuthenticationHandler.PATH_PROPERTY, value = { "/content/nextgen" }, cardinality = 100, propertyPrivate = false, label = "Path", description = "Repository path for which this authentication handler should be used by Sling. If this is empty, the authentication handler will be disabled."),
        @Property(name = "authtype", value = { "SAML" }, propertyPrivate = true) })
public class ShellCustomAuthenticationHandler extends AbstractAuthenticationHandler implements AuthenticationFeedbackHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ShellCustomAuthenticationHandler.class);
    private static final String CLASS_NAME = "ShellCustomAuthenticationHandler.class :: ";
    private static final String SAML_LOGIN_REQUEST_PATH = "/saml_login";

    @Property({ "1800" })
    public static final String OSGI_PROPERTY_SESSION_TIMEOUT_VALUE_IN_SEC = "sessionTimeoutValueInSeconds";

    @Property(label = "CDN Hexdecimal Key", description = "Enter CDN Hexdecimal key", value = "f6a1883aca2262ded6fe64a9")
    public static final String OSGI_PROPERTY_CDN_KEY = "cdnKey";

    @Property(label = "Enter ACLs for CDN", description = "Enter the list of URLs with prefix of \"external=\" or \"internal=\" then with suffix of experience : \"distributor\" or \"retail\"  or \"aviation\" and final the URL format like /content/nextgen/shell/{country}/{language}/{experience}/{agreement}", unbounded = PropertyUnbounded.ARRAY)
    private static final String OSGI_PROPERTY_CDN_ACLS = "cdnAcls";

    @Property(label = "URLs to bypass Authentication", description = "Enter the list of URLs using the add button where authentication is not needed.", unbounded = PropertyUnbounded.ARRAY)
    private static final String OSGI_PROPERTY_EXCLUDED_URLS_AUTHENTICATION = "excludedUrls";

    @Property(label = "Redirect Target URL", description = "Redirect URL on authentication failed", value = "f6a1883aca2262ded6fe64a9")
    public static final String OSGI_PROPERTY_REDIRECT_TARGET = "target"; 
    
    @Property(boolValue = true, label = "Redirect to Hybris Page?", description = "Redirect to hybris URL after authentication")
	private static final String HYBRIS_REDIRECT_SWITCH = "hybrisRedirectionSwtich";  
 

    @Reference
    ResourceResolverFactory resolverFactory;

    @Reference
    private LDAPAccessor ldapAccessor;

    @Reference
    private NGAPAccessor ngapAccessor;

    @Reference
    private StationaryDataService stationaryDataService;
    
    @Reference
    private TransactConfigurationService transactConfigService;

    @Reference
    private SlingRepository repository;

    @Reference
    private SlingSettingsService settings;

    @Reference(cardinality = ReferenceCardinality.OPTIONAL_UNARY, policy = ReferencePolicy.DYNAMIC)
    private Authenticator authenticator;
    
    @Reference
    private UserService userService;

    private String repositoryId;

    private String attrIp;

    private String attrAgent;

    private String alternateAuthUrl;

    private static final int DEFAULT_SESSION_TIMEOUT = 1800;
    private static final int PORT_NUMBER = 80;
    private static final String TERMS_AND_CONDITIONS_URL = "/content/nextgen/uam/termsAndConditionsAcceptance.acceptTermsConditions.html";
    private static final String PATH_TO_TERMS_AND_CONDTIONS = "/content/nextgen/uam/termsAndConditionsAcceptance";
    private static final String SAML_REQUEST_PATH = "saml_request_path";
    private static final String LOGIN_TRIAL = "login_trial";
    private static final String METHOD_SETMEDALLIACOOKIE = CLASS_NAME + "setMedalliaCookie :: ";

    private static final String METHOD_ACTIVATE = CLASS_NAME + "activate :: ";
    private static final String METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST = CLASS_NAME + "populateExternalAndInternalCDNUrlList :: ";
    private static final String METHOD_AUTHENTICATIONSUCCEEDED = CLASS_NAME + "authenticationSucceeded :: ";
    private static final String METHOD_EXTRACTCREDENTIALS = CLASS_NAME + "extractCredentials :: ";
    private static final String METHOD_REFRESHSESSIONTIMEOUT_COOKIE = CLASS_NAME + "refreshSessionTimeoutOnCookie :: ";
    private static final String METHOD_GETSAMLREQUESTPATHTARGETURL = CLASS_NAME + "getSamlRequestPathTargetURL :: ";
    private static final String METHOD_GENERATESHELLSESSION = CLASS_NAME + "generateShellSession :: ";
    private static final String METHOD_SETAKAMAICOOKIE = CLASS_NAME + "setAkamaiCookie :: ";
    private static final String METHOD_GENERATEUSERCDNURLS = CLASS_NAME + "generateUserCDNUrls :: ";
    private static final String METHOD_BUILDSHELLSESSION = CLASS_NAME + "buildShellSession :: ";
    private static final String METHOD_GETUSERSTARGETURL = CLASS_NAME + "getUsersTargetURL :: ";
    private static final String METHOD_REDIRECTTOTERMSANDCONDITONPAGE = CLASS_NAME + "redirectToTermsAndConditonPage :: ";
    private static final String METHOD_GETFIXSERVERURL = CLASS_NAME + "getFixServerURL :: ";
    private static final String METHOD_GETUSERNAME = CLASS_NAME + "getUserName :: ";
    private static final String METHOD_SETUSERPROFILETOSESSION = CLASS_NAME + "setUserProfileToSession :: ";
    private static final String METHOD_CHANGEDOMAINOFLOGINTOKENCOOKIETOSUPPORTMOTIVASITE = CLASS_NAME + "changeDomainOfLoginTokenCookieToSupportMotivaSite :: ";
    private static final String METHOD_ISSESSIONVALID = CLASS_NAME + "isSessionValid :: ";
    private static final String NO_TOKEN = "";
    private static final String REQUEST_METHOD = "POST";
    private static final String REQUEST_URL_SUFFIX = "/j_security_check";
    private static final String TC_URL = "/content/nextgen/uam/termsAndConditionsAcceptance.acceptTermsConditions.html";

    private static final String CREDENTIALS = "user.jcr.credentials";

    private static final String AUTH_TYPE = "TOKEN";

    private static final String ATTR_TOKEN = ".token";

    private static final String ATTR_TOKEN_IP_MANDATORY = ".token.ip";

    private static final String ATTR_TOKEN_AGENT_MANDATORY = ".token.useragent";

    private static final String ATTR_REFERER = "referer";

    private static final String REPO_DESC_ID = "crx.repository.systemid";

    private static final String REPO_DESC_CLUSTER_ID = "crx.cluster.id";

    private static final int CONVERT_SEC = 1000;

    private static final char[] NO_PASSWORD = new char[0];

    private static final String PAR_J_USERNAME = "j_username";

    private static final String PAR_J_PASSWORD = "j_password";

    private String defaultRedirectUrl;
    private String cdnKey;
    private List<String> cdnAcls;
    private List<String> extDistributorUrlList = new ArrayList<String>();
    private List<String> extCommonUrlList = new ArrayList<String>();
    private List<String> extRetailUrlList = new ArrayList<String>();
    private List<String> extAviationUrlList = new ArrayList<String>();
    private List<String> extLicensedMarketUrlList = new ArrayList<String>();
    private List<String> extEhaulierUrlList = new ArrayList<String>();
    private List<String> extGCSPLUrlList = new ArrayList<String>();
    private List<String> extGCOthersUrlList = new ArrayList<String>();
    private List<String> extGCMarineUrlList = new ArrayList<String>();
    private List<String> extGCAviationUrlList = new ArrayList<String>();
    private List<String> extGCfwsUrlList = new ArrayList<String>();
    private List<String> extGCb2bUrlList = new ArrayList<String>();
    private List<String> extGCcfUrlList = new ArrayList<String>();
    private List<String> intUrlList = new ArrayList<String>();
    private List<String> extWSUrlList = new ArrayList<String>();
    private List<String> extNewEnergiesUrlList = new ArrayList<String>();
    private List<String> extGCsfleetsolutionsUrlList = new ArrayList<String>();
    
    private int sessionTimeoutValueInSec = DEFAULT_SESSION_TIMEOUT;
    private TermsAndConditionSelector termsAndConditionsSelector;
    private List<String> bannedUrlsToSkip = new ArrayList<String>();
    private String target;
    private boolean redirectToHybris = false;
    private boolean isTransactUser = false;
    String currentOU = "";
    String currentLang = "";
    String currentUserName = "";
  
    @Activate
    public void activate(ComponentContext context) {
        LOG.debug(METHOD_ACTIVATE + GlobalConstants.ENTERING_METHOD);
        String id = this.repository.getDescriptor(REPO_DESC_CLUSTER_ID);
        if (id == null) {
            id = this.repository.getDescriptor(REPO_DESC_ID);
            if (id == null) {
                id = this.settings.getSlingId();
                if (id == null) {
                    id = UUID.randomUUID().toString();
                    LOG.error("activate: Failure to acquire unique ID for this token authenticator. Using random UUID {}", id);
                }
            }

        }

        
        
        this.repositoryId = id;
        LOG.debug("activate: Supporting tokens bound to Repository (Cluster) {}", this.repositoryId);

        // this.idpConfiguration = new IdpConfiguration();
        // this.defaultRedirectUrl = OsgiUtil.toString(context.getProperties().get(OSGI_PROPERTY_DEFAULT_REDIRECT_URL), "/");
        this.sessionTimeoutValueInSec = OsgiUtil.toInteger(context.getProperties().get(OSGI_PROPERTY_SESSION_TIMEOUT_VALUE_IN_SEC), DEFAULT_SESSION_TIMEOUT);
        this.cdnKey = OsgiUtil.toString(context.getProperties().get(OSGI_PROPERTY_CDN_KEY), "f6a1883aca2262ded6fe64a9");
        String[] cdnArray = OsgiUtil.toStringArray(context.getProperties().get(OSGI_PROPERTY_CDN_ACLS));
        if ((cdnArray == null) || (cdnArray.length == 0)) {
            this.cdnAcls = Collections.emptyList();
        } else {
            this.cdnAcls = Arrays.asList(cdnArray);
        }
        LOG.debug(METHOD_ACTIVATE + "CDN ACLs = " + this.cdnAcls);
        populateExternalAndInternalCDNUrlList();

        String[] excludedUrls = PropertiesUtil.toStringArray(context.getProperties().get(OSGI_PROPERTY_EXCLUDED_URLS_AUTHENTICATION));
        if ((excludedUrls != null) && (excludedUrls.length > 0)) {
            this.bannedUrlsToSkip = new ArrayList<String>(Arrays.asList(excludedUrls));
        }
        this.bannedUrlsToSkip = new ArrayList<String>(this.bannedUrlsToSkip);
        this.bannedUrlsToSkip.add("/system");
        this.bannedUrlsToSkip.add("/crx");

        this.target = OsgiUtil.toString(context.getProperties().get(OSGI_PROPERTY_REDIRECT_TARGET), "/nextgen-login/");
        // this.idpConfiguration.setIdpPostUrl(OsgiUtil.toString(context.getProperties().get(OSGI_PROPERTY_IDP_URL), ""));
        // super.activate(context);
        this.redirectToHybris = OsgiUtil.toBoolean(context.getProperties().get(HYBRIS_REDIRECT_SWITCH), false);
    }

    private void populateExternalAndInternalCDNUrlList() {
        LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + GlobalConstants.ENTERING_METHOD);
        for (String mainEntry : this.cdnAcls) {
            if (mainEntry.startsWith(GlobalConstants.CDN_EXTERNAL_URL_PREFIX)) {
                mainEntry = mainEntry.substring(GlobalConstants.CDN_EXTERNAL_URL_PREFIX.length());
                if (mainEntry.startsWith(GlobalConstants.DISTRIBUTOR)) {
                    mainEntry = mainEntry.substring(GlobalConstants.DISTRIBUTOR.length() + 1);
                    this.extDistributorUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.RETAIL)) {
                    mainEntry = mainEntry.substring(GlobalConstants.RETAIL.length() + 1);
                    this.extRetailUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.AVIATION)) {
                    mainEntry = mainEntry.substring(GlobalConstants.AVIATION.length() + 1);
                    this.extAviationUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.LICENSEDMARKET)) {
                    mainEntry = mainEntry.substring(GlobalConstants.LICENSEDMARKET.length() + 1);
                    this.extLicensedMarketUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.EHAULIER)) {
                    mainEntry = mainEntry.substring(GlobalConstants.EHAULIER.length() + 1);
                    this.extEhaulierUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.GCSPL)) {
                    mainEntry = mainEntry.substring(GlobalConstants.GCSPL.length() + 1);
                    this.extGCSPLUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.OTHERS)) {
                    mainEntry = mainEntry.substring(GlobalConstants.OTHERS.length() + 1);
                    this.extGCOthersUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.GCMARINE)) {
                    mainEntry = mainEntry.substring(GlobalConstants.GCMARINE.length() + 1);
                    this.extGCMarineUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.GCAVIATION)) {
                    mainEntry = mainEntry.substring(GlobalConstants.GCAVIATION.length() + 1);
                    this.extGCAviationUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.GCFWS)) {
                    mainEntry = mainEntry.substring(GlobalConstants.GCFWS.length() + 1);
                    this.extGCfwsUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.GC_B2B)) {
                    mainEntry = mainEntry.substring(GlobalConstants.GC_B2B.length() + 1);
                    this.extGCb2bUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.CF)) {
                    mainEntry = mainEntry.substring(GlobalConstants.CF.length() + 1);
                    this.extGCcfUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.ALL)) {
                    mainEntry = mainEntry.substring(GlobalConstants.ALL.length() + 1);
                    this.extCommonUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.WHOLESALER)) {
                    mainEntry = mainEntry.substring(GlobalConstants.WHOLESALER.length() + 1);
                    this.extWSUrlList.add(mainEntry);
                } else if (mainEntry.startsWith(GlobalConstants.SHELL_FLEET_SOLUTIONS)) {
                    mainEntry = mainEntry.substring(GlobalConstants.SHELL_FLEET_SOLUTIONS.length() + 1);
                	this.extGCsfleetsolutionsUrlList.add(mainEntry);
                }
                else if (mainEntry.startsWith(GlobalConstants.NEW_ENERGIES)) {
                    mainEntry = mainEntry.substring(GlobalConstants.NEW_ENERGIES.length() + 1);
                	this.extNewEnergiesUrlList.add(mainEntry);
                }
            } else if (mainEntry.startsWith(GlobalConstants.CDN_INTERNAL_URL_PREFIX)) {
                mainEntry = mainEntry.substring(GlobalConstants.CDN_INTERNAL_URL_PREFIX.length());
                this.intUrlList.add(mainEntry);
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "Internal URL Lists = " + this.intUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "External Distributor URL Lists = " + this.extDistributorUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "External Retail URL Lists = " + this.extRetailUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "External Aviation URL Lists = " + this.extAviationUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "External LicenseMarket URL Lists = " + this.extLicensedMarketUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "External WholeSaler URL Lists = " + this.extWSUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "External shell fleet solutions URL Lists = " + this.extGCsfleetsolutionsUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "External New Energies URL Lists = " + this.extNewEnergiesUrlList);
            LOG.debug(METHOD_POPULATEEXTERNALANDINTERNALCDNURLLIST + "Exiting from this method.");
        }
    }

    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {

        String samlRequestPathCookie = "";
        String loginTrialCookie = "";
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(SAML_REQUEST_PATH)) {
                    if (StringUtils.isNotBlank(cookie.getValue())) {
                        samlRequestPathCookie = cookie.getValue();                      
                    }
                }
                if (cookie.getName().equals(LOGIN_TRIAL)) {
                    if (StringUtils.isNotBlank(cookie.getValue())) {
                    	loginTrialCookie = cookie.getValue();                        
                    }
                }
            }
        }
        boolean redirectedToHybris = false;
        if (StringUtils.isNotBlank(samlRequestPathCookie) || StringUtils.isNotBlank(loginTrialCookie)) {
            LOG.info(METHOD_AUTHENTICATIONSUCCEEDED + "SAML Login Detected.");
            try {
                // String redirectUrl = getSamlRequestPathTargetURL(request.getCookies()); //request.getRequestURL().toString();
                clearRequestPathCookie(request, response, true);
                clearRequestPathCookie(request, response, false);
                String userHomePageUrl = generateShellSession(request, response, authInfo);
                if (StringUtils.isNotBlank(userHomePageUrl) && userHomePageUrl.contains(TC_URL)) {
                    response.sendRedirect(userHomePageUrl);
                    LOG.info("SHELL CUSTOM AUTHENTICATION HANDLER IS TRIGGERED after response");
                    return true;
                } else if (StringUtils.isBlank(userHomePageUrl)) {
                    LOG.error(METHOD_AUTHENTICATIONSUCCEEDED + "Failed to detect User's Homepage and SAML Request PATH");
                }
                //Redirection to hybris for transact users
				String redirectUrl = "";
				if (redirectToHybris && isTransactUser) {
					// Reading the redirect hybris URL from NGAP
					try {
						LOG.info("Custom Hybris redirection code executed");
						redirectUrl = ngapAccessor.getAllFavouriteLinks(currentUserName);						
					} catch (NGAPBaseException e) {
						LOG.error("Exception while calling getALlFavouriteLinks",e);
					}

					
					if (StringUtils.isNotEmpty(redirectUrl)) {

						// verify if the URL is valid
						if (redirectUrl.contains("nextgenstorefront") && redirectUrl.contains("currentOU")
								&& redirectUrl.contains("currentLang")) {
							
							// replace currentOU and currentLang string in the
							// redirect Url with actual values
							String finalRedirectUrl = redirectUrl.replace("currentOU", currentOU);
							finalRedirectUrl = finalRedirectUrl.replace("currentLang", currentLang);
							Map<String, String> transactMap = transactConfigService.getTransactURLs(currentOU, currentLang);
							if (null != transactMap && !transactMap.isEmpty() && transactConfigService.getTransactURLs(currentOU, currentLang).toString()
									.contains(finalRedirectUrl)) {
								LOG.info("Now redirecting to " + finalRedirectUrl);
								redirectedToHybris = true;
								response.sendRedirect(finalRedirectUrl);
                                return true;								
							}
						}
					}
				}
			} catch (IOException e) {
				LOG.error(METHOD_AUTHENTICATIONSUCCEEDED + "Could not read request.", e);
				LOG.debug(METHOD_AUTHENTICATIONSUCCEEDED + "Returning with value false.");
				return false;
			}
			LOG.debug(METHOD_AUTHENTICATIONSUCCEEDED + "Returning with value true.");

		}
        LOG.info(METHOD_AUTHENTICATIONSUCCEEDED + "Returning with DefaultAuthenticationFeedbackHandler method call.");
        if(!redirectedToHybris){
        	return DefaultAuthenticationFeedbackHandler.handleRedirect(request, response);
        }else return false;
    }

    public AuthenticationInfo extractCredentials(HttpServletRequest request, HttpServletResponse response) {
        LOG.debug(METHOD_EXTRACTCREDENTIALS + GlobalConstants.ENTERING_METHOD);
        boolean isSessionTrackerCookieValid = false;
        boolean isNextGenAuthCookieValid = false;
        boolean isLoginTokenCookieValid = false;
        Cookie sessionTrackerCookie = null;
        Cookie nextGenAuthCookie = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (GlobalConstants.SESSION_TRACKER_COOKIE.equals(cookie.getName())) {
                    isSessionTrackerCookieValid = true;
                    sessionTrackerCookie = cookie;
                }
                if (GlobalConstants.NEXT_GEN_AUTH_COOKIE.equals(cookie.getName())) {
                    isNextGenAuthCookieValid = true;
                    nextGenAuthCookie = cookie;
                }
                if (GlobalConstants.LOGIN_TOKEN_COOKIE.equals(cookie.getName())) {
                    isLoginTokenCookieValid = true;
                }
                if (isNextGenAuthCookieValid && isSessionTrackerCookieValid && isLoginTokenCookieValid) {
                    break;
                }
            }
        }
        String path = request.getServletPath() + ((request.getPathInfo() != null) ? request.getPathInfo() : "");
        refreshCookieExpirationTime(request, response, isSessionTrackerCookieValid, sessionTrackerCookie, nextGenAuthCookie, path);
        return createAuthenticationInfo(request, response, isSessionTrackerCookieValid, isNextGenAuthCookieValid, isLoginTokenCookieValid, path);
    }

    /**
     * @param request
     * @param response
     * @param isSessionTrackerCookieValid
     * @param sessionTrackerCookie
     * @param nextGenAuthCookie
     */
    private void refreshCookieExpirationTime(HttpServletRequest request, HttpServletResponse response, boolean isSessionTrackerCookieValid,
            Cookie sessionTrackerCookie, Cookie nextGenAuthCookie, String path) {

        if (LOG.isDebugEnabled()) {
            LOG.debug(METHOD_EXTRACTCREDENTIALS + "REQUESTED PAGE PATH : " + path);
            LOG.debug(METHOD_EXTRACTCREDENTIALS + "IS REQUEST VALID :: " + !AuthUtil.isValidateRequest(request));
            LOG.debug(METHOD_EXTRACTCREDENTIALS + "USER AGENT CONDITION:: " + AuthUtil.isBrowserRequest(request));
            LOG.debug(METHOD_EXTRACTCREDENTIALS + "AJAX REQUEST AND LOGIN LOOP DETECTION :: " + !AuthUtil.isAjaxRequest(request));
        }
        if (!isSessionTrackerCookieValid && (path.startsWith("/content") || path.startsWith("/apps"))) {
            LOG.debug(METHOD_EXTRACTCREDENTIALS + "@ INVALID SESSION DETECTED @");
            // return null;
        } else if (isSessionTrackerCookieValid && (path.startsWith("/content") || path.startsWith("/apps"))) {
            refreshSessionTimeoutOnCookie(request, response, sessionTrackerCookie);
            refreshSessionTimeoutOnCookie(request, response, nextGenAuthCookie);
            changeDomainOfLoginTokenCookieToSupportMotivaSite(request, response);
        }
    }

    private AuthenticationInfo createAuthenticationInfo(HttpServletRequest request, HttpServletResponse response, boolean isSessionTrackerCookieValid,
            boolean isNextGenAuthCookieValid, boolean isLoginTokenCookieValid, String path) {
        if (isSessionTrackerCookieValid && isNextGenAuthCookieValid && isLoginTokenCookieValid) {
            AuthenticationInfo userNameInfo = getTokenFormPars(request);
            if (userNameInfo != null) {
                request.setAttribute(REQUEST_URL_SUFFIX, AUTH_TYPE);
                return userNameInfo;
            }
            TokenCookie.Info info = TokenCookie.getTokenInfo(request, this.repositoryId);
            if (info.token != null) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Extracted token information: {}@{}", info.token, info.workspace);
                }

                if ((info.workspace != null) && (info.workspace.length() > 0)) {
                    request.setAttribute("j_workspace", info.workspace);
                }
                TokenCredentials creds = createCredentials(info.token);
                return createAuthenticationInfo(creds, request);
            }
        } else {
            boolean isAnonymousURL = false;
            for (String bannedURL : this.bannedUrlsToSkip) {
                if (path.startsWith(bannedURL)) {
                    isAnonymousURL = true;
                    break;
                }
            }
            ShellSessionHandler.getInstance().invalidateSession(request);
            CommonUtil.INSTANCE.cleanAllCookies(request, response);
            if (!isAnonymousURL) {
                AuthUtil.setLoginResourceAttribute(request, target);
                authenticator.logout(request, response);
            }

        }
        return null;
    }

    private void changeDomainOfLoginTokenCookieToSupportMotivaSite(HttpServletRequest request, HttpServletResponse response) {
        LOG.debug(METHOD_CHANGEDOMAINOFLOGINTOKENCOOKIETOSUPPORTMOTIVASITE + GlobalConstants.ENTERING_METHOD);
        LOG.debug(METHOD_CHANGEDOMAINOFLOGINTOKENCOOKIETOSUPPORTMOTIVASITE + "Checking presence of \"login-token\" cookie in request...");
        Cookie loginToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (GlobalConstants.LOGIN_TOKEN_COOKIE.equals(cookie.getName())) {
                    loginToken = cookie;
                    LOG.debug(METHOD_CHANGEDOMAINOFLOGINTOKENCOOKIETOSUPPORTMOTIVASITE
                            + "Cookie \"login-token\" found successfully in request. Now changing the domain of the cookie for Motiva Support.");
                    break;
                }
            }
        }
        String domain = "." + request.getServerName().replaceAll(GlobalConstants.DOMAIN_REGEXP, "");
        if (loginToken != null) {
            LOG.debug(METHOD_CHANGEDOMAINOFLOGINTOKENCOOKIETOSUPPORTMOTIVASITE + "New domain of \"login-token\" cookie is = " + domain);
            Cookie duplicateLoginTokenCookie = new Cookie(loginToken.getName() + "-hybris", loginToken.getValue());
            duplicateLoginTokenCookie.setDomain(domain);
            duplicateLoginTokenCookie.setMaxAge(loginToken.getMaxAge());
            duplicateLoginTokenCookie.setPath("/");
            response.addCookie(duplicateLoginTokenCookie);
        }
        LOG.debug(METHOD_CHANGEDOMAINOFLOGINTOKENCOOKIETOSUPPORTMOTIVASITE + GlobalConstants.EXITING_METHOD);
    }

    private void refreshSessionTimeoutOnCookie(HttpServletRequest request, HttpServletResponse response, Cookie cookie) {
        if (LOG.isDebugEnabled()) {
            LOG.debug(METHOD_REFRESHSESSIONTIMEOUT_COOKIE + GlobalConstants.ENTERING_METHOD);
            LOG.debug(METHOD_REFRESHSESSIONTIMEOUT_COOKIE + "@ REFRESHING COOKIE MAXAGE @");
        }
        String domain = "." + request.getServerName().replaceAll(GlobalConstants.DOMAIN_REGEXP, "");
        cookie.setMaxAge(this.sessionTimeoutValueInSec);
        cookie.setDomain(domain);
        cookie.setPath("/");
        LOG.debug(METHOD_REFRESHSESSIONTIMEOUT_COOKIE + "SESSION COOKIE : " + cookie.getName() + " :: " + cookie.getDomain() + " :: " + cookie.getMaxAge()
                + " :: " + cookie.getValue());
        response.addCookie(cookie);
        LOG.debug(METHOD_REFRESHSESSIONTIMEOUT_COOKIE + "Exiting from the method.");
    }

    private String getSamlRequestPathTargetURL(Cookie[] cookies) {
        LOG.debug(METHOD_GETSAMLREQUESTPATHTARGETURL + GlobalConstants.ENTERING_METHOD);
        String redirectUrl = null;
        if (cookies != null) {
            for (int index = 0; index < cookies.length; ++index) {
                Cookie cookie = cookies[index];
                if (SAML_REQUEST_PATH.equals(cookie.getName())) {
                    redirectUrl = cookie.getValue();
                    break;
                }
            }
        }
        LOG.debug(METHOD_GETSAMLREQUESTPATHTARGETURL + "Returning with redirectUrl = " + redirectUrl);
        return redirectUrl;
    }

    private boolean isSessionValid(HttpServletRequest request, HttpServletResponse response) {
        boolean isSessinValid = false;
        NGUserProfile userProfile = null;
        Object object = null;
        if (ShellSessionHandler.getInstance().isSessionValid(request)) {
            LOG.debug(METHOD_ISSESSIONVALID + "Existing Session has been detected. Restoring NGUserProfile object from session.");
            object = ShellSessionHandler.getInstance().getUserSession(request).get(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE);
            if (object instanceof NGUserProfile) {
                LOG.debug(METHOD_ISSESSIONVALID + "EXISTING REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));
                userProfile = (NGUserProfile) object;
                if (userProfile.get(GlobalConstants.CDN_COOKIE) != null && userProfile.get(GlobalConstants.HOMEPAGE) != null) {
                    isSessinValid = true;
                    LOG.debug(METHOD_ISSESSIONVALID + "User from session = " + userProfile);
                }
            } else if (object != null) {
                LOG.error(METHOD_ISSESSIONVALID + "EXISTING SESSION DETECTED BUT NGUSERPROFILE TYPE IS DIFFERENT");
                LOG.info(METHOD_ISSESSIONVALID + "NGUSERPROFILE TYPE = " + object.getClass().getName() + "OBJECT ID = " + object);
            }
        }
        return isSessinValid;
    }

    private String generateShellSession(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        LOG.debug(METHOD_GENERATESHELLSESSION + GlobalConstants.ENTERING_METHOD);
        NGUserProfile userProfile = null;
        Object object = null;

        if (ShellSessionHandler.getInstance().isSessionValid(request)) {
            //LOG.info(METHOD_GENERATESHELLSESSION + "Existing Session has been detected. Restoring NGUserProfile object from session.");
            object = ShellSessionHandler.getInstance().getUserSession(request).get(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE);
            if (object instanceof NGUserProfile) {
                LOG.info(METHOD_GENERATESHELLSESSION + "EXISTING REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));
                userProfile = (NGUserProfile) object;
                setAkamaiCookie(request, response, userProfile, authInfo);
                setMedalliaCookie(request, response, userProfile);
                LOG.debug(METHOD_GENERATESHELLSESSION + "User from session = " + userProfile);
                return getUsersTargetURL(request, response, userProfile);
            } else if (object != null) {
                LOG.error(METHOD_GENERATESHELLSESSION + "EXISTING SESSION DETECTED BUT NGUSERPROFILE TYPE IS DIFFERENT");
                LOG.info(METHOD_GENERATESHELLSESSION + "NGUSERPROFILE TYPE = " + object.getClass().getName() + "OBJECT ID = " + object);
            }
        } else {
            return buildShellSession(request, response, authInfo, userProfile);
        }
        return null;
    }

    private void setAkamaiCookie(HttpServletRequest request, HttpServletResponse response, NGUserProfile userProfile, AuthenticationInfo authInfo) {
        LOG.debug(METHOD_SETAKAMAICOOKIE + GlobalConstants.ENTERING_METHOD);
        String cdnCookieToken = null;
        if (userProfile != null && userProfile.get(GlobalConstants.CDN_COOKIE) == null) {
            List<SiteProfile> siteProfiles = userProfile.getUser().getSiteProfiles();
            UserTypeCode userType = userProfile.getUser().getUserTypeCode();
            long timeFromWhichTokenIsValid = (System.currentTimeMillis() / CONVERT_SEC) - (GlobalConstants.HOURS * GlobalConstants.MIN * GlobalConstants.SEC);
            ShellCookie shellCookieObject = null;
            StringBuilder userUrls = new StringBuilder();
            com.shell.b2b.cq.common.utils.CommonUtil utils = new com.shell.b2b.cq.common.utils.CommonUtil();
            String strUrl = "";
            ResourceResolver resolver = getResourceResolverFromRequest(request, authInfo);
            int index = 0;
            if (userType.equals(UserTypeCode.SAP_CRM_CUSTOMERADMIN) || userType.equals(UserTypeCode.SAP_CRM_NORMALUSER)
                    || userType.equals(UserTypeCode.SAP_CRM_SUPERSUSER) || userType.equals(UserTypeCode.NORMAL_USER)) {
                for (SiteProfile site : siteProfiles) {
                    String experience = site.getExperience();
                    String country = site.getSiteName();
                    country = utils.getCountryCode(country);
                    String market = site.getMarket();
                    Map<String, String> langMap = utils.getLanguageCodeForSiteSwitch(resolver, country, experience, market);
                    for (String language : langMap.keySet()) {
                    	
                        if (experience.equalsIgnoreCase(GlobalConstants.DISTRIBUTOR)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.DEX, country, language, market, this.extDistributorUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.RETAIL)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.RETAIL, country, language, market, this.extRetailUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.AVIATION)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.AVIATION, country, language, market, this.extAviationUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.LICENSEDMARKET)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.LICENSEDMARKET, country, language, market, this.extLicensedMarketUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.EHAULIER)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.EHAULIER, country, language, market, this.extEhaulierUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.GCSPL)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.GCSPL, country, language, market, this.extGCSPLUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.OTHERS)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.OTHERS, country, language, market, this.extGCOthersUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.GCMARINE)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.GCMARINE, country, language, market, this.extGCMarineUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.GCAVIATION)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.GCAVIATION, country, language, market, this.extGCAviationUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.GCFWS)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.GCFWS, country, language, market, this.extGCfwsUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.GC_B2B)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.GC_B2B, country, language, market, this.extGCb2bUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.CF)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.CF, country, language, market, this.extGCcfUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.WHOLESALER)) {
                            strUrl = generateUserCDNUrls(GlobalConstants.WHOLESALER, country, language, market, this.extWSUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.SHELL_FLEET_SOLUTIONS)) {
                        	strUrl = generateUserCDNUrls(GlobalConstants.SHELL_FLEET_SOLUTIONS, country, language, market, this.extGCsfleetsolutionsUrlList);
                        } else if (experience.equalsIgnoreCase(GlobalConstants.NEW_ENERGIES)) {
                        	strUrl = generateUserCDNUrls(GlobalConstants.NEW_ENERGIES, country, language, market, this.extNewEnergiesUrlList);
                        }
                        
                        LOG.debug("strUrl...inside loop : "+strUrl);
                        
                        if (index == 0) {
                            userUrls.append(strUrl);
                        } else {
                            userUrls.append(GlobalConstants.CDN_URL_DELIMITER).append(strUrl);
                        }
                        index++;
                    }
                }
                // add common path in cdn cookie
                if (index > 0) {
                	LOG.debug("strUrl...before..if index > 0 : "+strUrl);
                    strUrl = generateUserCDNUrls(null, null, null, null, this.extCommonUrlList);
                    userUrls.append(GlobalConstants.CDN_URL_DELIMITER).append(strUrl);
                    LOG.debug("strUrl...after..if index > 0:"+strUrl+" and userUrls: "+userUrls);
                }
                shellCookieObject = new ShellCookie(timeFromWhichTokenIsValid, GlobalConstants.CDN_MAXAGE, userUrls.toString(), this.cdnKey);
            } else {
                strUrl = generateUserCDNUrls("", "", "", "", this.intUrlList);
                shellCookieObject = new ShellCookie(timeFromWhichTokenIsValid, GlobalConstants.CDN_MAXAGE, strUrl.toString(), this.cdnKey);
            }
            if (shellCookieObject != null) {
                cdnCookieToken = shellCookieObject.getToken();
            }

        } else if (userProfile != null && userProfile.get(GlobalConstants.CDN_COOKIE) != null) {
            cdnCookieToken = (String) userProfile.get(GlobalConstants.CDN_COOKIE);
            LOG.info(METHOD_SETAKAMAICOOKIE + "RETRIEVING CDN_COOKIE VALUE FROM EXISTING SESSION " + cdnCookieToken);
        }
        Cookie cdnCookie = new Cookie(GlobalConstants.CDN_COOKIE, cdnCookieToken);
        String domain = "." + request.getServerName().replaceAll(GlobalConstants.DOMAIN_REGEXP, "");
        cdnCookie.setMaxAge(GlobalConstants.CDN_MAXAGE);
        cdnCookie.setDomain(domain);
        cdnCookie.setPath("/");
        response.addCookie(cdnCookie);
        userProfile.put(GlobalConstants.CDN_COOKIE, cdnCookieToken);
        LOG.debug(METHOD_SETAKAMAICOOKIE + "Exiting from this method.");
    }
    
    
    /**
  * @param request
  * @param response
  * @param userProfile
  * @param authInfo
  * @return
  */
 private void setMedalliaCookie(HttpServletRequest request, HttpServletResponse response, NGUserProfile userProfile){
 	try {
 		 LOG.debug(METHOD_SETMEDALLIACOOKIE + GlobalConstants.ENTERING_METHOD);
 		    if (userProfile != null) {
 		        UserTypeCode userType = userProfile.getUser().getUserTypeCode();
 		        String userName = userProfile.getUser().getUserName();
 		        List<SiteProfile> siteProfiles = userProfile.getUser().getSiteProfiles();
 		        StringBuilder medalliaCookieData =new StringBuilder();
 		        if (userType.equals(UserTypeCode.SAP_CRM_CUSTOMERADMIN) || userType.equals(UserTypeCode.SAP_CRM_NORMALUSER)
 		                || userType.equals(UserTypeCode.SAP_CRM_SUPERSUSER)) {
 		        	//we are using Userservice to disable this functionality for BOT accounts 
 		        	if (userName != null && userService != null && userService.getMedalliaUserAccess() != null
 		    				&& userService.getMedalliaUserAccess().contains(userName.toLowerCase())) {
 		        		LOG.info(userName + "Not having access");
 		    			
 		    		} else {
 		    			  for (SiteProfile site : siteProfiles) {
		        				medalliaCookieData.append("country"+":"+site.getSiteName()+"|");
		        				medalliaCookieData.append("language"+":"+site.getLangCode()+"|");
		        				medalliaCookieData.append("experience"+":"+site.getExperience()+"|");
		        				medalliaCookieData.append("market"+":"+site.getMarket());
		        			}
		        	  	Cookie medalliaCookie = new Cookie(GlobalConstants.MEDALLIA_COOKIE, medalliaCookieData.toString());
			 		    String domain = "." + request.getServerName().replaceAll(GlobalConstants.DOMAIN_REGEXP, "");
			 		    medalliaCookie.setMaxAge(GlobalConstants.MEDALLIA_MAXAGE);
			 		    medalliaCookie.setDomain(domain);
			 		    medalliaCookie.setPath("/");
			 		    response.addCookie(medalliaCookie);
			 		   LOG.info("Medallia cookie values" +medalliaCookie.toString());
 		    		}
 		        }
 		    }
 		LOG.debug(METHOD_SETMEDALLIACOOKIE + "Exiting from this method.");
 	} catch (ArrayIndexOutOfBoundsException e) {
 		LOG.error("Exception Occcurred in method setUserInfoCookie {}",e);
 	}
 }

    /**
     * @param userProfile
     * @param homePageUrl
     * @return
     */
    private String getCountry(NGUserProfile userProfile) {
        String country = null;
        String homePageUrl = (String) userProfile.get(GlobalConstants.HOMEPAGE);
        com.shell.b2b.cq.common.utils.CommonUtil commonUtil = new com.shell.b2b.cq.common.utils.CommonUtil();
        if (homePageUrl != null) {
            country = commonUtil.getOUFromPageUrl(homePageUrl);
        } else {
            String[] groupArr = CommonUtil.INSTANCE.getGroup(userProfile);
            if (groupArr != null && groupArr.length > GlobalConstants.ONE) {
                country = groupArr[GlobalConstants.ONE];
            }
        }
        return country;
    }

    private String generateUserCDNUrls(String experience, String country, String language, String agreement, List<String> cdnUrlExpressionList) {
        LOG.debug(METHOD_GENERATEUSERCDNURLS + GlobalConstants.ENTERING_METHOD);
        StringBuilder userUrls = new StringBuilder();

        for (int index = 0; index < cdnUrlExpressionList.size(); index++) {
            String strUrl = cdnUrlExpressionList.get(index);
            strUrl = StringUtils.replace(strUrl, GlobalConstants.CDN_URL_COUNTRY_TOKEN, country);
            strUrl = StringUtils.replace(strUrl, GlobalConstants.CDN_URL_LANGUAGE_TOKEN, language);
            strUrl = StringUtils.replace(strUrl, GlobalConstants.CDN_URL_AGREEMENT_TOKEN, agreement);
            strUrl = StringUtils.replace(strUrl, GlobalConstants.CDN_URL_EXPERIENCE_TOKEN, experience);
            try {
                strUrl = URLEncoder.encode(strUrl, "UTF-8");
                if (index == 0) {
                    userUrls.append(strUrl);
                } else {
                    userUrls.append(GlobalConstants.CDN_URL_DELIMITER).append(strUrl);
                }
            } catch (UnsupportedEncodingException e) {
                LOG.error("Failed to encode URL = " + strUrl, e);
            }
        }
        LOG.debug(METHOD_GENERATEUSERCDNURLS + "Returning from this method with value of userURLs = " + userUrls.toString());
        return userUrls.toString();
    }

    private String buildShellSession(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo, NGUserProfile userProfile) {
        String userName = getUserName(request, response, authInfo);
        if (StringUtils.isBlank(userName)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(METHOD_BUILDSHELLSESSION + "StringUtils.isBlank(userName) is true");
                LOG.debug(
                        METHOD_BUILDSHELLSESSION
                                + "Authentication succeeded, but the [SimpleCredentials] object retrieved with the [AuthenticationInfo] object's key [{}] does not contain a user name",
                        GlobalConstants.CREDENTIALS);
            }
            return null;
        }
        //LOG.debug(METHOD_BUILDSHELLSESSION + "Authentication succeeded for user name [{}]", userName);
        User user = HandlerUtil.getUserProfileFromNGAP(userName, ngapAccessor);
        isTransactUser = user.isTransactEnable();
        if (user == null) {
            LOG.debug(METHOD_BUILDSHELLSESSION + "error while ngapAccessor.findUserProfile for " + userName);
            return null;
        }
        //LOG.info("Site Profiles for " + user.getUserName() + ": " + user.getSiteProfiles().toString());
        userProfile = new NGUserProfile();
        UserTargetting useTragetting = new UserTargettingImpl();
        try {
            HandlerUtil.setLdapUserData(userProfile, userName, ldapAccessor);
            userProfile.setUser(user);
            stationaryDataService.updateSiteNameAndCOB(user.getSiteProfiles(), userProfile);
            HandlerUtil.setUserLocale(userProfile, request, user);
            setUserProfileToSession(request, userProfile, user, authInfo);
            useTragetting.setUserTargetting(user.getUserTargettingAttributes());
            userProfile.setUserTargetting(useTragetting);

            String siteUrl = getUsersTargetURL(request, response, userProfile);
            setAkamaiCookie(request, response, userProfile, authInfo);
            setMedalliaCookie(request, response, userProfile);
            String homePageUrl = (String) userProfile.get(GlobalConstants.HOMEPAGE);
            com.shell.b2b.cq.common.utils.CommonUtil commonUtil = new com.shell.b2b.cq.common.utils.CommonUtil();
            currentLang = commonUtil.getLanguageFromPageUrl(homePageUrl);
            currentOU = getCountry(userProfile);
            currentUserName = userName;
            return siteUrl;
        } catch (LDAPGetUserGroupsException e) {
            LOG.error(METHOD_BUILDSHELLSESSION + "LDAPGetUserGroupsException detected", e);
            return null;
        } catch (LDAPBaseException e) {
            LOG.error(METHOD_BUILDSHELLSESSION + "LDAPBaseException detected.", e);
            return null;
        } catch (LDAPException e) {
            LOG.error(METHOD_BUILDSHELLSESSION + "LDAPException detected", e);
            return null;
        }

    }

    private String getUsersTargetURL(HttpServletRequest request, HttpServletResponse response, NGUserProfile userProfile) {
        LOG.debug(METHOD_GETUSERSTARGETURL + GlobalConstants.ENTERING_METHOD);
        String siteUrl = null;
        String fixUrl = getFixServerURL(request);
        String targetUrl = request.getRequestURL().toString();
        targetUrl = targetUrl.substring(fixUrl.length(), targetUrl.length());
        LOG.debug(METHOD_GETUSERSTARGETURL + "TARGET URL :: " + targetUrl);
        if ((userProfile != null && userProfile.get(GlobalConstants.HOMEPAGE) == null)
                || (targetUrl.contains(TERMS_AND_CONDITIONS_URL) && userProfile.get(GlobalConstants.KEY_USER_PROFILE_TC) == null)) {
            if (targetUrl.contains(TERMS_AND_CONDITIONS_URL)) {
                LOG.debug(METHOD_GETUSERSTARGETURL + "TERMS AND CONDITIONS request detected");
                String resource = getLoginResource(request, null);
                try {
                    userProfile.put(GlobalConstants.KEY_USER_PROFILE_TC, "true");
                    response.sendRedirect(resource);
                } catch (IOException e) {
                    LOG.error(METHOD_GETUSERSTARGETURL + "Failed to send redirect to: " + resource, e);
                }
            } else {
                LOG.debug(METHOD_GETUSERSTARGETURL + "Failed to detect User's home page.");
                if (userProfile != null) {
                    SiteProfile siteProfile = MultisiteUtils.getActiveSite(userProfile.getUser().getSiteProfiles());
                    List<String> siteCobs = stationaryDataService.getListOfCobs(Integer.parseInt(siteProfile.getSiteId()), siteProfile.getExperience());
                    siteUrl = CommonUtil.INSTANCE.getSiteUrl(userProfile, siteCobs);
                    siteUrl = siteUrl != null ? GlobalConstants.NG_SHELL_DEX + siteUrl : siteUrl;
                }
                if (targetUrl != null && siteUrl != null) {
                    targetUrl = siteUrl;
                }
                LOG.debug(METHOD_GETUSERSTARGETURL + "CALCULATED Target URL :: " + targetUrl);
                targetUrl = redirectToTermsAndConditonPage(targetUrl, userProfile);
                LOG.debug(METHOD_GETUSERSTARGETURL + "FINAL Target URL After validating T&C business logic ::" + targetUrl);
                request.setAttribute(Authenticator.LOGIN_RESOURCE, targetUrl);
                LOG.debug(METHOD_GETUSERSTARGETURL + "FINAL USER SITE URL : " + siteUrl);
                userProfile.put(GlobalConstants.HOMEPAGE, siteUrl);
            }
        } else if (userProfile != null && userProfile.get(GlobalConstants.HOMEPAGE) != null) {
            targetUrl = (String) userProfile.get(GlobalConstants.HOMEPAGE);
            LOG.info(METHOD_GETUSERSTARGETURL + "RECOVERED FROM EXISTING USERPROFILE-Target URL :: " + targetUrl);
        }
        LOG.debug(METHOD_GETUSERSTARGETURL + "Returning with targetUrl : " + targetUrl);
        return targetUrl;
    }

    private String redirectToTermsAndConditonPage(String targetUrl, NGUserProfile userProfile) {
        // Check if terms&condition is updated or not if updated redirect to T&C page
        LOG.debug(METHOD_REDIRECTTOTERMSANDCONDITONPAGE + GlobalConstants.ENTERING_METHOD);
        String strTargetUrl = targetUrl;
        if (userProfile != null && !userProfile.isTocAcceptanceIsUpToDate()) {
            if (!strTargetUrl.startsWith(PATH_TO_TERMS_AND_CONDTIONS) && !strTargetUrl.startsWith(GlobalConstants.LOGOUT_URL)) {
                try {
                    strTargetUrl = PATH_TO_TERMS_AND_CONDTIONS + ".html?resource=" + URLEncoder.encode(strTargetUrl, "UTF-8");
                } catch (IOException e) {
                    LOG.error(METHOD_REDIRECTTOTERMSANDCONDITONPAGE + "Failed to redirect to accept terms and conditions page.", e);
                }
            }
        }
        LOG.debug(METHOD_REDIRECTTOTERMSANDCONDITONPAGE + "Returning with strTargetUrl = " + strTargetUrl);
        return strTargetUrl;
    }

    private String getFixServerURL(HttpServletRequest request) {
        LOG.debug(METHOD_GETFIXSERVERURL + GlobalConstants.ENTERING_METHOD);
        String fixUrl = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort();
        if (request.getServerPort() == PORT_NUMBER) {
            fixUrl = request.getScheme() + "://" + request.getServerName();
        }
        LOG.debug(METHOD_GETFIXSERVERURL + "Returning with fixUrl = " + fixUrl);
        return fixUrl;
    }

    protected void clearRequestPathCookie(HttpServletRequest request, HttpServletResponse response, boolean isDomain) {
        Cookie[] cookies = request.getCookies();
        String domain = "." + request.getServerName().replaceAll(".*\\.(?=.*\\.)", "");
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(SAML_REQUEST_PATH)) {
                    cookie.setMaxAge(0);
                    cookie.setValue("");
                    cookie.setPath("/");
                    if (isDomain) {
                        cookie.setDomain(domain);
                    }
                    response.addCookie(cookie);
                }
                if (cookie.getName().equals(LOGIN_TRIAL)) {
                    cookie.setMaxAge(0);
                    cookie.setValue("");
                    cookie.setPath("/");
                    if (isDomain) {
                        cookie.setDomain(domain);
                    }
                    response.addCookie(cookie);
                }
            }
        }
    }

    private String getUserName(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        LOG.debug(METHOD_GETUSERNAME + "Failed to detect existing session, therefore creating new session.");
        ShellSessionHandler.getInstance().createSessionUsingNextGenAuthToken(request, response);
        LOG.debug(METHOD_GETUSERNAME + "NEW REQUEST SESSIONID: " + ShellSessionHandler.getInstance().getShellSessionId(request));

        Credentials credentials = (Credentials) authInfo.get(GlobalConstants.CREDENTIALS);
        String userName = null;
        if (credentials == null) {
            LOG.debug(METHOD_GETUSERNAME + "credentials in ShellAuthenticationHandler is null");
            LOG.debug(METHOD_GETUSERNAME + "Authentication succeeded, but the [AuthenticationInfo] object has no key [{}]", GlobalConstants.CREDENTIALS);
            return null;
        } else if (credentials instanceof SimpleCredentials) {
            // Check if credentials are simple credentials
            LOG.debug(METHOD_GETUSERNAME + "credentials in ShellAuthenticationHandler is SimpleCredentials");
            userName = ((SimpleCredentials) credentials).getUserID();
        } else if (credentials instanceof TokenCredentials) {
            LOG.debug(METHOD_GETUSERNAME + "credentials in ShellAuthenticationHandler is TokenCredentials");
            ResourceResolver resourceResolver = getResourceResolverFromRequest(request, authInfo);
            userName = resourceResolver.getUserID();
        }
        return userName;
    }

    private void setUserProfileToSession(HttpServletRequest request, NGUserProfile userProfile, User user, AuthenticationInfo authInfo) {
        ResourceResolver resourceResolver = getResourceResolverFromRequest(request, authInfo);
        Session jcrSession = resourceResolver.adaptTo(Session.class);
        termsAndConditionsSelector = new TermsAndConditionSelector(jcrSession);
        String latestTermsAndConditions = termsAndConditionsSelector.getTermsAndConditionsVersion(userProfile);
        boolean tocAcceptanceIsUpToDate = latestTermsAndConditions.equals(user.getTocVersion());
        userProfile.setTocAcceptanceIsUpToDate(tocAcceptanceIsUpToDate);

        HttpSession session = request.getSession(true);
        session.setAttribute(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE, userProfile);

        LOG.info(METHOD_SETUSERPROFILETOSESSION + "USER : " + userProfile.getUser().getUserName() + " :: SHELL SESSION ID : "
                + ShellSessionHandler.getInstance().getShellSessionId(request));
        ShellSessionHandler.getInstance().getInitUserSession(request).put(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE, userProfile);
        LOG.info(METHOD_SETUSERPROFILETOSESSION + "ShellAuthenticationHandler FINAL EXIT : SHELL SESSION ID = "
                + ShellSessionHandler.getInstance().getShellSessionId(request) + " :: ========USER PROFILE CREATED===== \n " + userProfile);
    }

    /*
     * @Override public AuthenticationInfo extractCredentials(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse) { //
     * TODO Auto-generated method stub return null; }
     */

    public ResourceResolver getResourceResolverFromRequest(HttpServletRequest request, AuthenticationInfo authInfo) {
        LOG.debug("####" + "Entering inside the method.");
        ResourceResolver resourceResolver = null;

        Object obj = request.getAttribute("org.apache.sling.auth.core.ResourceResolver");
        if (obj != null && (obj instanceof ResourceResolver)) {
            resourceResolver = ((ResourceResolver) obj);
        } else
            try {
                resourceResolver = resolverFactory.getResourceResolver(authInfo);
            } catch (LoginException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        LOG.debug("#####" + "Returning with ResourceResolver = " + resourceResolver);
        return resourceResolver;
    }

    @Override
    public boolean requestCredentials(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse) throws IOException {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public void dropCredentials(HttpServletRequest paramHttpServletRequest, HttpServletResponse paramHttpServletResponse) throws IOException {
        // TODO Auto-generated method stub

    }

    private AuthenticationInfo createAuthenticationInfo(SimpleCredentials creds, HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        String ip;
        if (xff == null) {
            ip = request.getRemoteAddr();
        } else {
            String[] ips = xff.split(",");
            ip = ips[(ips.length - 1)].trim();
        }
        creds.setAttribute(this.attrIp, ip);

        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null) {
            creds.setAttribute(this.attrAgent, userAgent);
        }

        String referrer = request.getHeader("Referer");
        if (referrer != null) {
            creds.setAttribute(ATTR_REFERER, referrer);
        }

        AuthenticationInfo info = new AuthenticationInfo(AUTH_TYPE);
        info.put(CREDENTIALS, creds);
        return info;
    }

    private AuthenticationInfo createAuthenticationInfo(TokenCredentials creds, HttpServletRequest request) {
        String xff = request.getHeader("X-Forwarded-For");
        String ip;
        if (xff == null) {
            ip = request.getRemoteAddr();
        } else {
            String[] ips = xff.split(",");
            ip = ips[ips.length - 1].trim();
        }

        String lclAttrIp = !NO_TOKEN.equals(creds.getAttribute(ATTR_TOKEN)) ? ATTR_TOKEN_IP_MANDATORY : this.attrIp;
        creds.setAttribute(lclAttrIp, ip);

        String userAgent = request.getHeader("User-Agent");
        if (userAgent != null) {
            String lclAttrAgent = !NO_TOKEN.equals(creds.getAttribute(ATTR_TOKEN)) ? ATTR_TOKEN_AGENT_MANDATORY : this.attrAgent;
            creds.setAttribute(lclAttrAgent, userAgent);
        }

        String referrer = request.getHeader("Referer");
        if (referrer != null) {
            creds.setAttribute(ATTR_REFERER, referrer);
        }

        AuthenticationInfo info = new AuthenticationInfo(AUTH_TYPE);
        info.put(CREDENTIALS, creds);

        return info;
    }

    private AuthenticationInfo getTokenFormPars(HttpServletRequest request) {
        if ((REQUEST_METHOD.equals(request.getMethod())) && (isLoginURL(request)) && (request.getParameter(PAR_J_USERNAME) != null)) {
            if (!isValidateRequest(request)) {
                setLoginResourceAttribute(request, request.getContextPath());
            }

            SimpleCredentials creds = createCredentials(request.getParameter(PAR_J_USERNAME), request.getParameter(PAR_J_PASSWORD));

            return createAuthenticationInfo(creds, request);
        }
        return null;
    }

    private boolean isLoginURL(HttpServletRequest request) {
        boolean result = request.getRequestURI().endsWith(REQUEST_URL_SUFFIX);
        if ((!result) && (this.alternateAuthUrl != null)) {
            result = request.getRequestURI().endsWith(this.alternateAuthUrl);
        }
        return result;
    }

    private static TokenCredentials createCredentials(String token) {

        return new TokenCredentials(token);
    }

    private static SimpleCredentials createCredentials(String userId, String password) {
        SimpleCredentials creds = new SimpleCredentials(userId, password != null ? password.toCharArray() : NO_PASSWORD);

        creds.setAttribute(ATTR_TOKEN, NO_TOKEN);
        return creds;
    }
}
