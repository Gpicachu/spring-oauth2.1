package org.dromara.oauth2.authorization.token;

import jakarta.servlet.http.HttpServletRequest;
import org.dromara.oauth2.constant.OAuth2Constant;
import org.dromara.oauth2.utils.SecurityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.*;

public class TokenGrantAuthenticationConverter implements AuthenticationConverter {

    static final String ACCESS_TOKEN_REQUEST_ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

    @Override
    public Authentication convert(HttpServletRequest request) {
        // grant_type (REQUIRED)
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
        //if (!SecurityConstants.GRANT_TYPE_SMS_CODE.equals(grantType)) {
        if (!OAuth2Constant.GRANT_TYPE_TOKEN.equals(grantType)) {
            return null;
        }

        // 这里目前是客户端认证信息
        Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();

        // 获取请求中的参数
        MultiValueMap<String, String> parameters = SecurityUtils.getParameters(request);

        // scope (OPTIONAL)
        String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
        if (StringUtils.hasText(scope) &&
            parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
            SecurityUtils.throwError(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "OAuth 2.0 Parameter: " + OAuth2ParameterNames.SCOPE,
                ACCESS_TOKEN_REQUEST_ERROR_URI);
        }
        Set<String> requestedScopes = null;
        if (StringUtils.hasText(scope)) {
            requestedScopes = new HashSet<>(
                Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
        }

        // Mobile phone number (REQUIRED)
        //String username = parameters.getFirst(SecurityConstants.OAUTH_PARAMETER_NAME_PHONE);
        String username = parameters.getFirst(OAuth2Constant.AUTHORITIES_TOKEN);
        if (!StringUtils.hasText(username) || parameters.get(OAuth2Constant.AUTHORITIES_TOKEN).size() != 1) {
            SecurityUtils.throwError(
                OAuth2ErrorCodes.INVALID_REQUEST,
                "OAuth 2.0 Parameter: " + OAuth2Constant.AUTHORITIES_TOKEN,
                ACCESS_TOKEN_REQUEST_ERROR_URI);
        }

        // SMS verification code (REQUIRED)
//        String password = parameters.getFirst(SecurityConstants.OAUTH_PARAMETER_NAME_SMS_CAPTCHA);
//        if (!StringUtils.hasText(password) || parameters.get(SecurityConstants.OAUTH_PARAMETER_NAME_SMS_CAPTCHA).size() != 1) {
//            SecurityUtils.throwError(
//                OAuth2ErrorCodes.INVALID_REQUEST,
//                "OAuth 2.0 Parameter: " + SecurityConstants.OAUTH_PARAMETER_NAME_SMS_CAPTCHA,
//                ACCESS_TOKEN_REQUEST_ERROR_URI);
//        }

        // 提取附加参数
        Map<String, Object> additionalParameters = new HashMap<>();
        parameters.forEach((key, value) -> {
            if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) &&
                !key.equals(OAuth2ParameterNames.CLIENT_ID)) {
                additionalParameters.put(key, value.get(0));
            }
        });

        // 构建AbstractAuthenticationToken子类实例并返回
        return new TokenGrantAuthenticationToken(new AuthorizationGrantType(OAuth2Constant.GRANT_TYPE_TOKEN), clientPrincipal, requestedScopes, additionalParameters);
    }

}
