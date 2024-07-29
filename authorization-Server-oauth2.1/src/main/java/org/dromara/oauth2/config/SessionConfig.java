package org.dromara.oauth2.config;

import jakarta.annotation.Resource;
import org.dromara.oauth2.authorization.support.RedisOperator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.session.web.http.CookieHttpSessionIdResolver;
import org.springframework.session.web.http.DefaultCookieSerializer;
import org.springframework.session.web.http.HttpSessionIdResolver;

@Configuration
public class SessionConfig {

    @Resource
    private RedisOperator<String> redisOperator;

    @Bean
    public HttpSessionIdResolver httpSessionIdResolver() {
        DefaultCookieSerializer cookieSerializer = new DefaultCookieSerializer();
        if(redisOperator.isEmpty("sys_config:sys.oss.previewListResource")) {
            cookieSerializer.setCookieMaxAge(Integer.valueOf(redisOperator.get("sys_config:sys.oss.previewListResource").toString())); // 设置 Session 超时时间为 4 小时
        }
        cookieSerializer.setCookieMaxAge(14400); // 设置 Session 超时时间为 4 小时
        cookieSerializer.setCookieName("JSESSIONID");
        cookieSerializer.setCookiePath("/");

        CookieHttpSessionIdResolver resolver = new CookieHttpSessionIdResolver();
        resolver.setCookieSerializer(cookieSerializer);

        return resolver;
    }
}
