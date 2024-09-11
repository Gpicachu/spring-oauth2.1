package org.dromara.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.context.metrics.buffering.BufferingApplicationStartup;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;

@EnableRedisHttpSession(maxInactiveIntervalInSeconds = 14400)
@ComponentScan("org.dromara.oauth2.*")
@EnableScheduling
@SpringBootApplication
public class BaseOAuth2Application {
    public static void main(String[] args) {
        SpringApplication application = new SpringApplication(BaseOAuth2Application.class);
        application.setApplicationStartup(new BufferingApplicationStartup(2048));
        application.run(args);
        System.out.println("(♥◠‿◠)ﾉﾞ  用户认证授权中心启动成功   ლ(´ڡ`ლ)ﾞ  ");
    }
}
