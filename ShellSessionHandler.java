package com.shell.b2b.cq.common.sessionhandler;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.day.cq.wcm.api.WCMMode;
import com.shell.b2b.cq.common.cacheMap.LRUMapWithExpiry;
import com.shell.cq.common.bean.NGUserProfile;
import com.shell.cq.common.constants.GlobalConstants;

public class ShellSessionHandler {

    private static final Logger LOG = LoggerFactory.getLogger(ShellSessionHandler.class);
    private static ShellSessionHandler singletonObject = new ShellSessionHandler();
    private static final String SESSION_TRACKER = GlobalConstants.SESSION_TRACKER_COOKIE;
    private static final String CRX_LOGIN_TOKEN = "login-token";
    private static final String SESSION_ATTRIBUTES = "smh-session-attributes";
    
    private String sessionToken = CRX_LOGIN_TOKEN;

    private LRUMapWithExpiry<String, Map<String, Object>> map = new LRUMapWithExpiry<String, Map<String, Object>>(2100, 3, 5000);

    private ShellSessionHandler() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("CREATING SINGLETON INSTANCE OF ShellSessionHandler.java");
        }
    }

    public static ShellSessionHandler getInstance() {
        if (LOG.isDebugEnabled()) {
            LOG.debug("RETURNING SINGLETON INSTANCE OF ShellSessionHandler.java");
        }
        return singletonObject;
    }

    public String getShellSessionId(HttpServletRequest request) {
        String shellSessionId = "NO_SESSION";
        Object sessionIdValue = request.getAttribute(sessionToken);
        if (sessionIdValue != null) {
            shellSessionId = (String) sessionIdValue;
            if (LOG.isDebugEnabled()) {
                LOG.debug("CURRENT SESSION ID VIA REQUEST ATTRIBUTE : " + shellSessionId);
            }
        } else {
            if (request.getCookies() != null) {
                shellSessionId = getSessionIdValueFromCookie(request);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("CURRENT SESSION ID VIA COOKIE : " + shellSessionId);
                }
            }
        }
        return shellSessionId;
    }
    
    public Map<String, Object> getUserSession(HttpServletRequest request) {
    	return getUserSession(request,3);
    }
    
    public Map<String, Object> getUserSession(HttpServletRequest request,int numberOfTrys) {
        Map<String, Object> result = null;
        Object sessionIdValue = request.getAttribute(sessionToken);
        if (sessionIdValue != null) {
            String mapKey = (String) sessionIdValue;
            if (isPublishMode(request)) {
            	result = fetchUserSession(mapKey,numberOfTrys);
            } else {
            	result = map.get(mapKey);
            }
        } else {
            if (request.getCookies() != null) {
                sessionIdValue = getSessionIdValueFromCookie(request);
                if (sessionIdValue != null) {
                    String mapKey = (String) sessionIdValue;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("SHELL SESSION FOUND SUCCESSFULLY with ID = " + mapKey);
                    }
                    if (isPublishMode(request)) {
                    	result = fetchUserSession(mapKey);
                    } else {
                    	result = map.get(mapKey);
                    }
                }
            }
        }
        return result;
    }
    
    private boolean isPublishMode(HttpServletRequest request) {
    	return WCMMode.fromRequest(request).equals(WCMMode.DISABLED);
    }
    
    private Map<String, Object> fetchUserSession(String mapKey) {
    	return fetchUserSession(mapKey,3);
    }
    
    private Map<String, Object> fetchUserSession(String mapKey,int numberOfTrys) {
    	Map<String, Object> session = map.get(mapKey);
    	LOG.info("Retrieved user session key is " + mapKey);
    	if (!isProfileAvailable(session)) {
    		int tryCount = 0;
    		while (tryCount < numberOfTrys && !isProfileAvailable(session)) {
    			tryCount ++;
    			
    			if(tryCount>2) {
    				LOG.info("Retrying user session: " + tryCount);
    				for(StackTraceElement s:Thread.currentThread().getStackTrace()) {
    					LOG.info("[STACK]" + s.getClassName() + "." + s.getMethodName()
    			        + "(" + s.getFileName() + ":" + s.getLineNumber() + ")");
    				}
    			}
    			else {
    				LOG.info("Retrying user session: " + tryCount);
    			}
    			
    			waitForRetry();
    			session = map.get(mapKey);
    			LOG.info("Retrieved user session after tries :" + tryCount + " Session:" + session);
    		}
    	}
    	LOG.info("Finally returning session: " + session);
    	return session;
    }
    
    public Map<String, Object> getInitUserSession(HttpServletRequest request) {
    	LOG.info("Calling INIT User Session for Authhandler.");
        Map<String, Object> result = null;
        Object sessionIdValue = request.getAttribute(sessionToken);
        if (sessionIdValue != null) {
            String mapKey = (String) sessionIdValue;
            result = map.get(mapKey);
        } else {
            if (request.getCookies() != null) {
                sessionIdValue = getSessionIdValueFromCookie(request);
                if (sessionIdValue != null) {
                    String mapKey = (String) sessionIdValue;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("SHELL SESSION FOUND SUCCESSFULLY with ID = " + mapKey);
                    }
                    result = map.get(mapKey);
                }
            }
        }
        return result;
    }
    
    private boolean isProfileAvailable(Map<String, Object> session) {
    	//LOG.info("Is Profile Available: " + (session != null && !session.isEmpty() && session.containsKey(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE)));
    	return (session != null && !session.isEmpty() && session.containsKey(NGUserProfile.SESSION_ATTRIBUTE_USER_PROFILE));
    }
    
    private void waitForRetry() {
    	try {
			TimeUnit.MILLISECONDS.sleep(1000);
		} catch (InterruptedException e) {
			LOG.warn("Thread Interrupted: ", e);
		}
    }

    private String getSessionIdValueFromCookie(HttpServletRequest request) {
        String sessionIdValue = null;
        if (request.getCookies() != null) {
            Cookie[] cookieArray = request.getCookies();
            for (Cookie cookie : cookieArray) {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("COOKIE KEY = " + cookie.getName() + " :: VALUE = " + cookie.getValue() + "\n");
                }
                if (cookie.getName().equals(sessionToken)) {
                    sessionIdValue = cookie.getValue();
                    break;
                }
            }
        }
        return sessionIdValue;
    }
    
    public void invalidateSession(HttpServletRequest request){
    	String sessionIdValue = getSessionIdValueFromCookie(request);
    	if(sessionIdValue!=null){
    		LOG.debug("GOING TO INVALIDATE SESSION HAVING SESSION ID = " + sessionIdValue);
    		map.remove(sessionIdValue);
    	}
    }

    public void createSessionUsingNextGenAuthToken(HttpServletRequest request, HttpServletResponse response){
    	this.sessionToken = SESSION_TRACKER;
    	createSession(request,response);
    }
    
    public void createSession(HttpServletRequest request, HttpServletResponse response) {
        String sessionIdValue = getSessionIdValueFromCookie(request);
        map.put(sessionIdValue, new HashMap<String, Object>());
        request.setAttribute(this.sessionToken, sessionIdValue);
    }

    public boolean isSessionValid(HttpServletRequest request) {

        boolean isSessionValid = false;
        Object sessionIdValue = request.getAttribute(sessionToken);
        if (sessionIdValue != null && StringUtils.isNotBlank((String) sessionIdValue) && map.get((String) sessionIdValue) != null) {
            isSessionValid = true;
            if (LOG.isDebugEnabled()) {
                LOG.debug("isSessionValid() :: VIA REQUEST ATTRIBUTE : " + isSessionValid);
            }
        } else {
            if (request.getCookies() != null) {
                String strSessionIdValue = getSessionIdValueFromCookie(request);
                if (strSessionIdValue != null && map.get(strSessionIdValue) != null) {
                    isSessionValid = true;
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("isSessionValid() :: VIA COOKIE : " + isSessionValid);
                    }
                } else {
                    if (LOG.isDebugEnabled()) {
                        LOG.debug("isSessionValid() :: NO SESSION VIA COOKIE : SHELL SESSION ID : " + strSessionIdValue);
                    }
                }
            } else {
                if (LOG.isDebugEnabled()) {
                    LOG.debug("isSessionValid() :: NO SESSION :: COOKIES NOT PRESENT.");
                }
            }
        }
        if (LOG.isDebugEnabled()) {
            LOG.debug("IS SESSION VALID : " + isSessionValid);
        }
        return isSessionValid;
    }
    
    public void addSessionAttribute(HttpServletRequest request, String attrName, Object attrValue) {
    	Map<String, Object> sessionObject = getUserSession(request);
    	if (sessionObject != null && StringUtils.isNotBlank(attrName) && attrValue != null) {
    		Map<String, Object> sessionAttributes = (Map<String, Object>)sessionObject.get(SESSION_ATTRIBUTES);
    		if (sessionAttributes == null) {
    			sessionAttributes = new HashMap<String, Object>();
    			sessionObject.put(SESSION_ATTRIBUTES, sessionAttributes);
    		}
    		sessionAttributes.put(attrName, attrValue);
    	}
    }
    
    public Object getSessionAttribute(HttpServletRequest request, String attrName) {
    	Map<String, Object> sessionObject = getUserSession(request);
    	if (sessionObject != null) {
    		Map<String, Object> sessionAttributes = (Map<String, Object>)sessionObject.get(SESSION_ATTRIBUTES);
    		if (sessionAttributes != null) {
    			return sessionAttributes.get(attrName);
    		}
    	}
    	return null;
    }

}
