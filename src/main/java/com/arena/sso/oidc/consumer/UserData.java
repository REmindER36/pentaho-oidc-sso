package com.arena.sso.oidc.consumer;

/**
 * @author reminder63
 * Date: 08.12.2017
 * Time: 15:10
 */
public class UserData
{
    private String tenantId;
    private String userName;
    private String[] roles;
    
    public UserData(String tenantId, String userName, String[] roles)
    {
        this.tenantId = tenantId;
        this.userName = userName;
        this.roles = roles;
    }
    
    public String getTenantId()
    {
        return tenantId;
    }
    
    public String getUserName()
    {
        return userName;
    }
    
    public String[] getRoles()
    {
        return roles;
    }
}