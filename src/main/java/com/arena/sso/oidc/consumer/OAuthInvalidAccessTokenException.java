package com.arena.sso.oidc.consumer;

/**
 * @author reminder63
 * Date: 07.02.2018
 * Time: 18:59
 */
public class OAuthInvalidAccessTokenException extends  OAuthConsumerException
{
    public OAuthInvalidAccessTokenException(String message)
    {
        super(message);
    }
    
    public OAuthInvalidAccessTokenException(String message, Throwable cause)
    {
        super(message, cause);
    }
}