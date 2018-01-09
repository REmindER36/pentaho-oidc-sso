package com.arena.sso.oidc;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author reminder63
 * Date: 08.12.2017
 * Time: 15:20
 */
public interface OAuthUserDetailsService extends UserDetailsService
{
    UserDetails loadUser(String user, String[] roles) throws UsernameNotFoundException;
    
    UserDetails loadUser(String tenantId, String userName, String[] roles) throws UsernameNotFoundException;
}
