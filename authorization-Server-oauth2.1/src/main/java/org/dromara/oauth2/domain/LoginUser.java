package org.dromara.oauth2.domain;


import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.Assert;

import java.io.Serial;
import java.io.Serializable;
import java.util.Collection;
import java.util.List;
import java.util.Set;

/**
 * 用户信息
 *
 * @author base
 */
@Data
@JsonSerialize
@JsonIgnoreProperties(ignoreUnknown = true)
public class LoginUser  implements UserDetails, Serializable{

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * 用户唯一标识
     */
    private String token;

    /**
     * 用户名id
     */
    private Long userid;

    /**
     * 用户名
     */
    private String username;

    /**
     * 用户名
     */
    private String phone;

    /**
     * 密码
     */
    private String password;


    /**
     * 登录时间
     */
    private Long loginTime;

    /**
     * 过期时间
     */
    private Long expireTime;

    /**
     * 登录IP地址
     */
    private String ipaddr;

    /**
     * 应用id
     */
    private String clientId;

    /**
     * 应用有几次多次认证
     */
    private String clientSeveralTimes;


    /**
     * 应用是否启用多次认证 当前多次认证次数
     */
    private String clientSeveralTimesNow;


    /**
     * 二次认证类型
     */
    private String clientSeveralTwoType;


    /**
     * 用户信息
     */
    private SysUser sysUser;

    /**
     * 扩展字段：用户ID
     */
    private Long userId;

    /**
     * 扩展字段：部门ID
     */
    private Long deptId;

    /**
     * 用户角色数据权限集合
     */
    private Integer dataScope;

    /**
     * 默认字段
     */
    private Boolean enabled;
    private Collection<GrantedAuthority> authorities;

    private boolean accountNonExpired = true;

    private boolean accountNonLocked = true;

    private boolean credentialsNonExpired = true;

    private Set<String> perms;


    public LoginUser() {
        this.setEnabled(true);
    }

    /**
     * 系统管理用户
     */
    public LoginUser(SysUser user) {
        List<GrantedAuthority> createAuthority = AuthorityUtils.createAuthorityList("admin");
        this.setUsername(user.getUserName());
        this.setDeptId(user.getDeptId());
        this.setPassword("{bcrypt}" + user.getPassword());
        this.setEnabled(true);
        this.setAuthorities(createAuthority);
        this.setSysUser(user);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return this.enabled;
    }

}

