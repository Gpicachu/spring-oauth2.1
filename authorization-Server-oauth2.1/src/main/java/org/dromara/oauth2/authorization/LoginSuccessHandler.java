package org.dromara.oauth2.authorization;

import cn.hutool.extra.spring.SpringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.dromara.oauth2.config.CustomSecurityProperties;
import org.dromara.oauth2.utils.JsonUtils;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * 登录成功处理类
 *
 * @author vains
 */
@Slf4j
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    private static final CustomSecurityProperties customSecurityProperties = SpringUtil.getBean(CustomSecurityProperties.class);

    private RequestCache requestCache = new HttpSessionRequestCache();

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        log.debug("登录成功.");
        if("JSON".equals(customSecurityProperties.getResponseType())) {
            Result<String> success = Result.success();
            response.setCharacterEncoding(StandardCharsets.UTF_8.name());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(JsonUtils.objectCovertToJson(success));
            response.getWriter().flush();
        }else{
            //重定向到上次请求的地址上，引发跳转到认证页面的地址
            SavedRequest savedRequest = this.requestCache.getRequest(request, response);
            String targetUrl = savedRequest.getRedirectUrl();
            if (targetUrl != null) {
                targetUrl = targetUrl.replaceFirst("&continue","");
                targetUrl = targetUrl.replaceFirst("/oauth", "/org/dromara/oauth2/oauth");
                targetUrl = targetUrl.replaceFirst("http://iam.bmp.uat.cfca.com.cn/","https://iam.bmp.uat.cfca.com.cn/");
                targetUrl = targetUrl.replaceFirst("http://iam.bmp.sit.cfca.com.cn/","https://iam.bmp.sit.cfca.com.cn/");
            }
            response.sendRedirect(targetUrl);
        }

    }

}
