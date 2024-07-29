package org.dromara.oauth2.config;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import lombok.RequiredArgsConstructor;
import org.dromara.oauth2.authorization.LoginFailureHandler;
import org.dromara.oauth2.authorization.LoginSuccessHandler;
import org.dromara.oauth2.utils.SecurityUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.session.HttpSessionCreatedEvent;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.CorsFilter;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(jsr250Enabled = true, securedEnabled = true)
public class SpringSecurityConfig {

    private final CorsFilter corsFilter;

    /**
     * 不需要认证即可访问的路径
     */
    private final CustomSecurityProperties customSecurityProperties;

    /**
     * 配置认证相关的过滤器链
     *
     * @param http spring security核心配置类
     * @return 过滤器链
     * @throws Exception 抛出
     */
    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

        // 添加跨域过滤器
        http.addFilter(corsFilter);
        // 禁用 csrf 与 cors
        http.csrf(AbstractHttpConfigurer::disable);
        http.cors(AbstractHttpConfigurer::disable);
        //SecurityUtils.applyBasicSecurity(http, corsFilter, customSecurityProperties);
        http.authorizeHttpRequests((authorize) -> authorize
            // 放行静态资源和不需要认证的url
            .requestMatchers(customSecurityProperties.getIgnoreUriList().toArray(new String[0])).permitAll()
            .anyRequest().authenticated()
        )
            // 指定登录页面
            .formLogin(formLogin ->{
                formLogin.loginPage("/login");
                formLogin.loginProcessingUrl("/token/from");
                formLogin.successHandler(new LoginSuccessHandler());
                formLogin.failureHandler(new LoginFailureHandler());
            });

        // 添加BearerTokenAuthenticationFilter，将认证服务当做一个资源服务，解析请求头中的token
        http.oauth2ResourceServer((resourceServer) -> resourceServer
            .jwt(Customizer.withDefaults())
            .accessDeniedHandler(SecurityUtils::exceptionHandler)
            .authenticationEntryPoint(SecurityUtils::exceptionHandler)
        );
        return http.build();
    }


}
