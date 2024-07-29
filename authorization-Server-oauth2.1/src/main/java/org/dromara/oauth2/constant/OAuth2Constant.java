package org.dromara.oauth2.constant;

public class OAuth2Constant {

    /**
     * 随机字符串请求头名字
     */
    public static final String NONCE_HEADER_NAME = "nonce";

    /**
     * 密码模式（自定义）
     */
    public static final String GRANT_TYPE_PASSWORD = "password";


    /**
     * 短信验证码模式（自定义）
     */
    public static final String GRANT_TYPE_TOKEN = "authorization_token";

    /**
     * 短信验证码
     */
    public static final String AUTHORITIES_TOKEN = "token";


    /**
     * 权限在token中的key
     */
    public static final String AUTHORITIES_KEY = "authorities";

    /**
     * 构造方法私有化
     */
    private OAuth2Constant(){

    }
}
