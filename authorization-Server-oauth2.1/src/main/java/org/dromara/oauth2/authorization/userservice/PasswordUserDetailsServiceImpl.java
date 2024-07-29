package org.dromara.oauth2.authorization.userservice;

import jakarta.annotation.Resource;
import org.dromara.oauth2.domain.LoginUser;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;


/**
 * @author picachu
 * @version 1.0
 * @date 2024/7/26-16:24
 * @description TODO
 */
@Component("PasswordUserDetailsServiceImpl")
public class PasswordUserDetailsServiceImpl implements UserDetailsService {

    //@Resource
    //private SysUserService sysUserService;

    @Resource
    private PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String token) throws UsernameNotFoundException {

        //SysUserEntity sysUserEntity = sysUserService.selectByUsername(username);
//        if(Objects.isNull(sysUserEntity)){
//            throw new UsernameNotFoundException("用户不存在！");
//        }
        System.out.println(token);
        List<GrantedAuthority> createAuthority = AuthorityUtils.createAuthorityList("admin");
        System.out.println(token);
        LoginUser user = new LoginUser();
        user.setUsername("yangcai1");
        user.setPassword(passwordEncoder.encode("666777"));
        user.setAuthorities(createAuthority);
        user.setUserid(2L);

        return user;
    }
}
