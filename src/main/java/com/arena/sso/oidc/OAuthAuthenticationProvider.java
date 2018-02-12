package com.arena.sso.oidc;

import com.arena.sso.oidc.consumer.OAuthConsumerException;
import com.arena.sso.oidc.consumer.AccessToken;
import org.pentaho.platform.api.engine.IPentahoSession;
import org.pentaho.platform.engine.core.system.PentahoSessionHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;


/**
 * Authentication provider to get UserDetails object using the identity of given OAuthPreAuthenticationToken as username,
 * and to create an authenticated OAuthAuthenticationToken. *
 */
public class OAuthAuthenticationProvider implements AuthenticationProvider, InitializingBean {
    
    private static final Logger log = LoggerFactory.getLogger(OAuthAuthenticationProvider.class);
    
    //~ Instance fields ================================================================================================
    
    private OAuthUserDetailsService userDetailsService;
    private GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    //~ Methods ========================================================================================================

    @Override
    public void afterPropertiesSet() {
        Assert.notNull(this.userDetailsService, "The userDetailsService must be set");
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        if (!supports(authentication.getClass())) {
            return null;
        }
        OAuthPreAuthenticationToken preAuthenticationToken = (OAuthPreAuthenticationToken) authentication;

        AccessToken accessToken = preAuthenticationToken.getAccessToken();
        UserDetails userDetails;
        try
        {
            userDetails = userDetailsService.loadUser(accessToken.getTenantId(), accessToken.getPrefferedUserName(),accessToken.getRoles());
            IPentahoSession pentahoSession = PentahoSessionHolder.getSession();
            pentahoSession.setAttribute("access.token", accessToken.toString());
            log.info("Session Access Token: {}", pentahoSession.getAttribute("access.token"));
        }
        catch (Exception e)
        {
            throw new OAuthConsumerException("User loading failed", e);
        }
        return new OAuthAuthenticationToken(this.authoritiesMapper.mapAuthorities(userDetails.getAuthorities()), accessToken.getPrefferedUserName());
    }

    @Override
    public boolean supports(Class authentication) {
        return OAuthPreAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setUserDetailsService(OAuthUserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }
}
