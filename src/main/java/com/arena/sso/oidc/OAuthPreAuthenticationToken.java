package com.arena.sso.oidc;

import com.arena.sso.oidc.consumer.AccessToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

/**
 * The only need to specify special type of AuthenticationToken for OAuth pre-authentication purposes.
 */
public class OAuthPreAuthenticationToken extends PreAuthenticatedAuthenticationToken {

    private AccessToken accessToken;
    
    public OAuthPreAuthenticationToken(AccessToken accessToken) {
        super(accessToken.getPrefferedUserName(), "");
        this.accessToken = accessToken;
    }
    
    public AccessToken getAccessToken()
    {
        return accessToken;
    }
}
