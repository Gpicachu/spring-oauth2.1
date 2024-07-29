package org.dromara.oauth2.authorization.captcha;

import jakarta.servlet.http.HttpServletRequest;
import cn.hutool.extra.spring.SpringUtil;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.dromara.oauth2.authorization.userservice.PasswordUserDetailsServiceImpl;
import org.dromara.oauth2.authorization.userservice.UserDetailsServiceImpl;
import org.dromara.oauth2.constant.OAuth2Constant;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Objects;

/**
 * 验证码校验
 * 注入ioc中替换原先的DaoAuthenticationProvider
 * 在authenticate方法中添加校验验证码的逻辑
 * 最后调用父类的authenticate方法并返回
 *
 * @author picachu
 */
@Slf4j
public class CaptchaAuthenticationProvider extends DaoAuthenticationProvider {

    /**
     * 利用构造方法在通过{@link Component}注解初始化时
     * 注入UserDetailsService和passwordEncoder，然后
     * 设置调用父类关于这两个属性的set方法设置进去
     *
     * @param userDetailsService 用户服务，给框架提供用户信息
     * @param passwordEncoder    密码解析器，用于加密和校验密码
     */
    public CaptchaAuthenticationProvider(UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        super.setPasswordEncoder(passwordEncoder);
        super.setUserDetailsService(userDetailsService);
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        log.info("Authenticate captcha...");

        // 获取当前request
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new RuntimeException("Failed to get the current request.");
        }
        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();

        // 获取当前登录方式
        String loginType = request.getParameter("loginType");
         loginType = StringUtils.isEmpty(loginType)?request.getParameter("grant_type"):loginType;
        if (Objects.equals(loginType, OAuth2Constant.GRANT_TYPE_TOKEN)) {
            // 只要不是密码登录都不需要校验图形验证码
            log.info("It isn't necessary captcha authenticate.");
            super.setUserDetailsService(SpringUtil.getBean(UserDetailsServiceImpl.class));
            return super.authenticate(authentication);
        }

        if (Objects.equals(loginType, OAuth2Constant.GRANT_TYPE_PASSWORD)) {
            // 只要不是密码登录都不需要校验图形验证码
            log.info("It isn't necessary captcha authenticate.");
            super.setUserDetailsService(SpringUtil.getBean(PasswordUserDetailsServiceImpl.class));
            return super.authenticate(authentication);
        }

        log.info("Captcha authenticated.");
        return super.authenticate(authentication);
    }
}
