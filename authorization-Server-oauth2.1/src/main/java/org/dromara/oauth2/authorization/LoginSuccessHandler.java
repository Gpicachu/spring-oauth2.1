package org.dromara.oauth2.authorization;

import cn.hutool.extra.spring.SpringUtil;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.dromara.oauth2.config.CustomSecurityProperties;
import org.dromara.oauth2.utils.JsonUtils;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
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
    private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

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
            String targetUrl =savedRequest == null?"http://127.0.0.1:8080/oauth2/authorize?client_id="+
                    request.getParameter("client_id")+"&response_type=code&token="+
                    request.getParameter("token"): savedRequest.getRedirectUrl();

            if (targetUrl != null) {
                targetUrl = targetUrl.replaceFirst("&continue","");
                //targetUrl = targetUrl.replaceFirst("/oauth", "/oauth/oauth2");
            }
            //response.sendRedirect(targetUrl);
            this.redirectStrategy.sendRedirect(request, response, targetUrl);
        }

    }

}
