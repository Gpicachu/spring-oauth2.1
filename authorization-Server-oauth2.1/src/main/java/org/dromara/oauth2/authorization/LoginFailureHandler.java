package org.dromara.oauth2.authorization;

import cn.hutool.extra.spring.SpringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import org.dromara.oauth2.config.CustomSecurityProperties;
import org.dromara.oauth2.utils.JsonUtils;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 登录失败处理类
 *
 * @author vains
 */
@Slf4j
public class LoginFailureHandler implements AuthenticationFailureHandler {

    private static final CustomSecurityProperties customSecurityProperties = SpringUtil.getBean(CustomSecurityProperties.class);


    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException {
        log.debug("登录失败，原因：{}", exception.getMessage());
        if("JSON".equals(customSecurityProperties.getResponseType())) {
            // 登录失败，写回401与具体的异常
            Result<String> success = Result.error(HttpStatus.UNAUTHORIZED.value(), exception.getMessage());
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(JsonUtils.objectCovertToJson(success));
            response.getWriter().flush();
        } else {
            // 获取上一次请求路径
            String referer = request.getHeader("Referer");
            log.info("referer:" + referer);
            // 如果下面有值,则认为是多端登录,直接返回一个登录地址
            Object toAuthentication = request.getAttribute("toAuthentication");
            String lastUrl = toAuthentication != null ? customSecurityProperties.getLoginUrl()
                : StringUtils.substringBefore(referer, "?");
            log.info("上一次请求的路径 ：" + lastUrl);
            response.sendRedirect(lastUrl + "?error=" + exception.getLocalizedMessage());
        }

    }

}
