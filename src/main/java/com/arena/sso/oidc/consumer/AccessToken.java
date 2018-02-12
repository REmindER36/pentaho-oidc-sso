package com.arena.sso.oidc.consumer;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.jwt.JwtHelper;

/**
 * @author reminder63
 * Date: 08.12.2017
 * Time: 15:10
 */
public class AccessToken
{
    private static final Logger log = LoggerFactory.getLogger(AccessToken.class);
    
    private String accessToken;
    private JSONObject decodedToken;
    
    public AccessToken(String accessToken) throws OAuthInvalidAccessTokenException {
        this.accessToken = accessToken;
        try
        {
            this.decodedToken = new JSONObject(JwtHelper.decode(accessToken).getClaims());
        } catch (JSONException ex) {
            throw new OAuthInvalidAccessTokenException("Error parsing access token", ex);
        }
    }
    
    public String getName() {
        return safeGetStringValue("name");
    }
    
    public String getTenantId()
    {
        return safeGetStringValue("tenant-id");
    }
    
    public String getPrefferedUserName()
    {
        return safeGetStringValue("preferred_username");
    }
    
    public String getGivenName() {
        return safeGetStringValue("given_name");
    }
    
    public String getFamilyName() {
        return safeGetStringValue("family_name");
    }
    
    public String[] getRoles()
    {
        JSONArray jsonArray = safeGetJsonArray(safeGetJsonObject("realm_access"), "roles");
        String [] result = new String[jsonArray.length()];
        for(int i=0; i < jsonArray.length(); i++) {
            result[i] = safeGetStringValue(jsonArray, i);
        }
        return result;
    }
    
    private String safeGetStringValue(String fieldName) {
        try {
            return decodedToken.getString(fieldName);
        } catch (JSONException ex) {
            log.warn("Error get string data from Access Token. Field: " + fieldName, ex);
            return "";
        }
    }
    
    private String safeGetStringValue(JSONArray jsonArray, int index) {
        try {
            return jsonArray.getString(index);
        } catch (JSONException ex) {
            log.warn("Error get element from json array.", ex);
            return "";
        }
    }
    
    private JSONObject safeGetJsonObject(String fieldName) {
        try {
            return decodedToken.getJSONObject(fieldName);
        } catch (JSONException ex) {
            log.warn("Error get object data from Access Token. Field: " + fieldName, ex);
            return new JSONObject();
        }
    }
    
    private JSONArray safeGetJsonArray(JSONObject jsonObject, String fieldName) {
        try {
            return jsonObject.getJSONArray(fieldName);
        } catch (JSONException ex) {
            log.warn("Error get array data from Access Token. Field: " + fieldName, ex);
            return new JSONArray();
        }
    }
    
    @Override
    public String toString()
    {
        return accessToken;
    }
}