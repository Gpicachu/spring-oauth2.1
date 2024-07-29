package org.dromara.oauth2.authorization.password;

import cn.hutool.core.util.StrUtil;
import jakarta.servlet.http.HttpServletRequest;
import org.dromara.oauth2.utils.SecurityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * 密码模式参数解析器
 * <p>
 * 解析请求参数中的用户名和密码，并构建相应的身份验证(Authentication)对象
 *
 * @author picachu
 * @see org.springframework.security.oauth2.server.authorization.web.authentication.OAuth2AuthorizationCodeAuthenticationConverter
 * @since 3.0.0
 */
public class PasswordAuthenticationConverter implements AuthenticationConverter {

    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";


    @Override
    public Authentication convert(HttpServletRequest request) {

        // 授权类型 (必需)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
            return null;
        }

        // 客户端信息
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // 参数提取验证
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>(parameterMap.size());
        parameterMap.forEach((key, values) -> {
            if (values.length > 0) {
                for (String value : values) {
                    parameters.add(key, value);
                }
            }
        });

        // 令牌申请访问范围验证 (可选)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
                parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            SecurityUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.SCOPE,
                ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // 用户名验证(必需)
        String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
        if (StrUtil.isBlank(username)) {
            SecurityUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.USERNAME,
                ACCESS_TOKEN_REQUEST_ERROR_URI
            );
        }

        // 密码验证(必需)
        String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
        if (StrUtil.isBlank(password)) {
            SecurityUtils.throwError(
                    OAuth2ErrorCodes.INVALID_REQUEST,
                    OAuth2ParameterNames.PASSWORD,
                ACCESS_TOKEN_REQUEST_ERROR_URI
            );
        }

        // 附加参数(保存用户名/密码传递给 PasswordAuthenticationProvider 用于身份认证)
        Map<String, Object> additionalParameters = parameters
                .entrySet()
                .stream()
                .filter(e -> !e.getKey().equals(OAuth2ParameterNames.GRANT_TYPE) &&
                        !e.getKey().equals(OAuth2ParameterNames.SCOPE)
                ).collect(Collectors.toMap(Map.Entry::getKey, e -> e.getValue().get(0)));

        return new PasswordAuthenticationToken(
                clientPrincipal,
                requestedScopes,
                additionalParameters
        );
    }


}
