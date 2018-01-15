package com.arena.sso.oidc.consumer;

import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URLDecoder;
import java.util.Arrays;

/**
 * @author reminder63
 * Date: 13.12.2017
 * Time: 20:13
 */
public class OAuthOnlyTokenConsumerImpl implements OAuthConsumer
{
    private static final Logger log = LoggerFactory.getLogger(OAuthOnlyTokenConsumerImpl.class);
    private static final String ACCESS_TOKEN_COOKIE_NAME = "sessionService";
    
    private String openIdClaim;
    
    @Override
    public String handleLoginRequest(HttpServletRequest request) throws OAuthConsumerException
    {
        return null;
    }
    
    @Override
    public UserData handleAuthenticationRequest(HttpServletRequest request) throws OAuthConsumerException
    {
        String username;
        String tenantId = null;
        String[] roles;
        String authenticationTokenUri;
        try
        {
            Cookie globalsCookie = Arrays.stream(request.getCookies())
                    .filter(cookie -> cookie.getName().equals(ACCESS_TOKEN_COOKIE_NAME))
                    .findAny()
                    .orElseThrow(() -> new OAuthConsumerException("Failed get cookies 'globals'"));
    
            String ssoInfoJson = URLDecoder.decode(globalsCookie.getValue(), "UTF-8");
            log.info("[AUTH-SSO] 1. Get Access Token From cookies. '{}' = {}", ACCESS_TOKEN_COOKIE_NAME, ssoInfoJson);
            JSONObject ssoInfo = new JSONObject(ssoInfoJson);
            String accessToken = ssoInfo.getString("_accessToken");
            Jwt token = JwtHelper.decode(accessToken);
            String tokenJson = token.getClaims();
            roles = parseRoles(tokenJson);
            log.info("[AUTH-SSO] 1.1 Parsed roles from Access Token: '{}'.", roles);
            try
            {
                tenantId = parseTenant(tokenJson);
            } catch (JSONException e)
            {
                log.error("Error parse tenant-id from Access Token", e);
            }
            log.info("[AUTH-SSO] 1.2 Parsed tenant id from Access Token: '{}'.", tenantId);
            
            JSONObject tokenData = new JSONObject(token.getClaims());
            authenticationTokenUri = tokenData.getString("iss") + "/protocol/openid-connect/userinfo";
            
            log.info("[AUTH-SSO] 2 Request 'userinfo' to :" + authenticationTokenUri);
            HttpResponse responseUsername = sendGetRequest(authenticationTokenUri, accessToken);
            String cont = EntityUtils.toString(responseUsername.getEntity());
            JSONObject jsonContent = new JSONObject(cont);
            log.info("[AUTH-SSO] 3. JSON Response is:" + jsonContent);
            String userWemail = jsonContent.getString(openIdClaim);
            String[] userparts = userWemail.split("@");
            log.info("[AUTH-SSO] 4 Response is:" + userparts[0]);
            username = userparts[0];
            
        }
        catch (Exception e)
        {
            log.info("[AUTH-SSO] RESPONSE ERROR :" + e);
            throw new OAuthConsumerException("The exception occurred when tried communicate with identity provider service", e);
        }
        return new UserData(tenantId, username, roles);
    }
    
    private String[] parseRoles(String token) throws JSONException
    {
        JSONObject tokenData = new JSONObject(token);
        JSONArray rolesJson = tokenData.getJSONObject("realm_access").getJSONArray("roles");
        String[] result = new String[rolesJson.length()];
        for (int i=0; i < rolesJson.length(); i++)
        {
            result[i] = rolesJson.getString(i);
        }
        return result;
    }
    
    
    private String parseTenant(String token) throws JSONException
    {
        JSONObject tokenData = new JSONObject(token);
        String tenantName = tokenData.getString("tenant-id");
        return tenantName;
    }
    
    
    private HttpResponse sendGetRequest(String authenticationTokenFullUri, String accessToken) throws IOException
    {
        HttpClient httpclient = HttpClients.createDefault();
        HttpGet httpget = new HttpGet(authenticationTokenFullUri);
        // for GET calls that require Auth Bearer in HTTP HEADERs e.g. WSO2 IdP, add Auth header
        httpget.setHeader("Authorization", "Bearer " + accessToken);
        log.info("[AUTH-SSO] SEND modified HTTPGET for :" + authenticationTokenFullUri + " with Auth Bearer:" + accessToken);
        //Execute and return the response.
        return httpclient.execute(httpget);
    }
    
    public void setOpenIdClaim(String openIdClaim)
    {
        this.openIdClaim = openIdClaim;
    }
}