package org.dromara.oauth2.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.dromara.oauth2.authorization.Result;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import java.util.*;

@Controller
public class AuthorizationController {

    private RequestCache requestCache = new HttpSessionRequestCache();

    @GetMapping("/login")
    public ModelAndView login(HttpServletRequest request, HttpServletResponse response) {
        ModelAndView view = new ModelAndView();
        String error = request.getParameter("error");
        if (error != null) {
            //view.setViewName(errorUrl + error);
        }
        String client_id = "";
        String response_type = "";
        String token = "";
        String redirect_uri = "";
        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (null != savedRequest) {
            Map<String, String[]> targetUrl1 = savedRequest.getParameterMap();
            String[] client_idZ = targetUrl1.get("client_id");
            String[] response_typeZ = targetUrl1.get("response_type");
            String[] tokenZ = targetUrl1.get("token");
            String[] redirect_uriZ = targetUrl1.getOrDefault("redirect_uri",null);
            if (client_idZ != null) {
                client_id = client_idZ[0];
                response_type = response_typeZ[0];
                if (tokenZ != null) {
                    token = tokenZ[0];
                }
                request.getSession(false).setAttribute("client_id", client_id);
            } else {
                client_id = (String) request.getSession(false).getAttribute("client_id");
            }
            if (redirect_uriZ != null) {
                redirect_uri =redirect_uriZ[0];
            }
        }
        view.addObject("client_id", client_id);
        view.addObject("response_type", response_type);
        view.addObject("token", token);
        view.addObject("redirect_uri", redirect_uri);
        if ("".equals(token)) {
            //需要写成动态配置地址
            //view.addObject("httpuri", "https://iam.bmp.uat.cfca.com.cn/");
            //view.setViewName("/loginZ/gateway");
        } else {
            String sessionCode3 =request.getSession().getId();
            System.err.println("sessionCode3:"+request.getSession().getId());
            //JSONObject object = new JSONObject();
            //object.put("sessionCode3",redisService.getExpire("iam:sessions:expires:"+sessionCode3));
            //redisService.expire("iam:sessions:expires:"+sessionCode3,  (long) 7200, TimeUnit.SECONDS);
            view.setViewName("/login");
        }
//        sysLogService.send(new YtJSONObject(request).put("username", "").put("operaFlag","0")
//                .put("resultFlag","0").put("operation","104").put("remarks","").put("clientId",client_id)
//                .put("outputJsonData", JSONObject.toJSONString(request.getParameterMap()))
//                .put("inputJsonData", JSONObject.toJSONString(view.getModelMap())).getHome());
        return view;
    }

    @GetMapping("/thirdPartyLoginMe")
    public ModelAndView thirdPartyLoginMe(HttpServletRequest request, HttpServletResponse response) {
        ModelAndView view = new ModelAndView();
        String code = request.getParameter("code");
        view.addObject("code", code);
        view.setViewName("/thirdPartyLoginMe");
        return view;
    }


    @GetMapping("/org/dromara/oauth2/userinfo")
    @ResponseBody
    public Result<Map> userinfo(JwtAuthenticationToken authentication) {
        Map<String,Object> user = new HashMap<>();
        user.put("userName",authentication.getName());
        user.put("userId",authentication.getToken().getClaims().get("userId").toString());
        return Result.success(user);
    }




}
