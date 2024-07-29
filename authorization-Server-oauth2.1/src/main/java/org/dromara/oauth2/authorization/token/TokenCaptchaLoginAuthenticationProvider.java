package org.dromara.oauth2.authorization.token;

import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.ObjectUtils;
import org.dromara.oauth2.authorization.captcha.CaptchaAuthenticationProvider;
import org.dromara.oauth2.constant.OAuth2Constant;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.Objects;

/**
 * 短信验证码校验实现
 *
 * @author picachu
 */
@Slf4j
@Component
public class TokenCaptchaLoginAuthenticationProvider extends CaptchaAuthenticationProvider {

    /**
     * 利用构造方法在通过{@link Component}注解初始化时
     * 注入UserDetailsService和passwordEncoder，然后
     * 设置调用父类关于这两个属性的set方法设置进去
     *
     * @param userDetailsService 用户服务，给框架提供用户信息
     * @param passwordEncoder    密码解析器，用于加密和校验密码
     */
    public TokenCaptchaLoginAuthenticationProvider(@Qualifier("UserDetailsServiceImpl") UserDetailsService userDetailsService, PasswordEncoder passwordEncoder) {
        super(userDetailsService, passwordEncoder);
    }


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 获取当前request
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new RuntimeException("无法获取当前请求.");
        }
        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
        // 获取 /token是请求的类型
        String grantType = request.getParameter("grant_type");
        // 获取Token
        String token = request.getParameter("token");

        // 非空校验
        if (Objects.equals(grantType, OAuth2Constant.GRANT_TYPE_TOKEN) && ObjectUtils.isEmpty(token) ) {
            throw new BadCredentialsException("Token不能为空.");
        }

        String username = request.getParameter("username");
        String password = request.getParameter("password");

        if(Objects.equals(grantType, OAuth2Constant.GRANT_TYPE_PASSWORD) && ObjectUtils.isEmpty(username) ) {
            throw new BadCredentialsException("认证信息不能为空.");
        }
        UsernamePasswordAuthenticationToken unauthenticated;

        //分类型认证  pwd是的认证参数是用户名  密码   别的不是
        if(Objects.equals(grantType, OAuth2Constant.GRANT_TYPE_PASSWORD)) {
            unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated(username, password);
        }else {
            unauthenticated = UsernamePasswordAuthenticationToken.unauthenticated(token, token);
        }

        unauthenticated.setDetails(new WebAuthenticationDetails(request));

        return super.authenticate(unauthenticated);
    }



    @Override
    protected void additionalAuthenticationChecks(UserDetails userDetails, UsernamePasswordAuthenticationToken authentication) throws AuthenticationException {
        log.info("开始进行身份验证...");

        if (authentication.getCredentials() == null) {
            this.logger.debug("由于未提供凭据，因此无法进行身份验证");
            throw new BadCredentialsException("验证参数不能为空.");
        }

        // 获取当前request
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (requestAttributes == null) {
            throw new RuntimeException("无法获取当前请求.");
        }
        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();

        // 获取当前登录方式
        String loginType = request.getParameter("loginType");
        // 获取grant_type
        String grantType = request.getParameter("grant_type");
        // 短信登录和自定义短信认证grant type会走下方认证
        // 如果是自定义密码模式则下方的认证判断只要判断下loginType即可
        if (Objects.equals(loginType, OAuth2Constant.GRANT_TYPE_TOKEN)
            || Objects.equals(grantType, OAuth2Constant.GRANT_TYPE_TOKEN)) {
        // 在这里也可以拓展其它登录方式，比如邮箱登录什么的
        } else {
            log.info("Not sms captcha loginType, exit.");
            // 其它调用父类默认实现的密码方式登录
            super.additionalAuthenticationChecks(userDetails, authentication);
        }

        log.info("经过身份验证.");
    }
}
