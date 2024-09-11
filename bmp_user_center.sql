/*
 Navicat Premium Data Transfer

 Source Server         : user-server
 Source Server Type    : MySQL
 Source Server Version : 80032 (8.0.32)
 Source Host           : 29.0.0.79:3316
 Source Schema         : bmp_user_center

 Target Server Type    : MySQL
 Target Server Version : 80032 (8.0.32)
 File Encoding         : 65001

 Date: 11/09/2024 15:20:22
*/

SET NAMES utf8mb4;
SET FOREIGN_KEY_CHECKS = 0;

-- ----------------------------
-- Table structure for oauth2_authorization
-- ----------------------------
DROP TABLE IF EXISTS `oauth2_authorization`;
CREATE TABLE `oauth2_authorization` (
  `id` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `registered_client_id` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `principal_name` varchar(200) COLLATE utf8mb4_general_ci NOT NULL,
  `authorization_grant_type` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `authorized_scopes` varchar(1000) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `attributes` blob,
  `state` varchar(500) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `authorization_code_value` blob,
  `authorization_code_issued_at` datetime DEFAULT NULL,
  `authorization_code_expires_at` datetime DEFAULT NULL,
  `authorization_code_metadata` blob,
  `access_token_value` blob,
  `access_token_issued_at` datetime DEFAULT NULL,
  `access_token_expires_at` datetime DEFAULT NULL,
  `access_token_metadata` blob,
  `access_token_type` varchar(100) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `access_token_scopes` varchar(1000) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `oidc_id_token_value` blob,
  `oidc_id_token_issued_at` datetime DEFAULT NULL,
  `oidc_id_token_expires_at` datetime DEFAULT NULL,
  `oidc_id_token_metadata` blob,
  `refresh_token_value` blob,
  `refresh_token_issued_at` datetime DEFAULT NULL,
  `refresh_token_expires_at` datetime DEFAULT NULL,
  `refresh_token_metadata` blob,
  `user_code_value` blob,
  `user_code_issued_at` datetime DEFAULT NULL,
  `user_code_expires_at` datetime DEFAULT NULL,
  `user_code_metadata` blob,
  `device_code_value` blob,
  `device_code_issued_at` datetime DEFAULT NULL,
  `device_code_expires_at` datetime DEFAULT NULL,
  `device_code_metadata` blob,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of oauth2_authorization
-- ----------------------------
BEGIN;
COMMIT;

-- ----------------------------
-- Table structure for oauth2_authorization_consent
-- ----------------------------
DROP TABLE IF EXISTS `oauth2_authorization_consent`;
CREATE TABLE `oauth2_authorization_consent` (
  `registered_client_id` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `principal_name` varchar(200) COLLATE utf8mb4_general_ci NOT NULL,
  `authorities` varchar(1000) COLLATE utf8mb4_general_ci NOT NULL,
  PRIMARY KEY (`registered_client_id`,`principal_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of oauth2_authorization_consent
-- ----------------------------
BEGIN;
COMMIT;

-- ----------------------------
-- Table structure for oauth2_registered_client
-- ----------------------------
DROP TABLE IF EXISTS `oauth2_registered_client`;
CREATE TABLE `oauth2_registered_client` (
  `id` varchar(100) COLLATE utf8mb4_general_ci NOT NULL,
  `client_id` varchar(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci NOT NULL COMMENT '客户端ID',
  `client_id_issued_at` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `client_secret` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL COMMENT '客户端密钥',
  `client_secret_expires_at` datetime DEFAULT NULL,
  `client_name` varchar(200) COLLATE utf8mb4_general_ci NOT NULL,
  `client_authentication_methods` varchar(1000) COLLATE utf8mb4_general_ci NOT NULL,
  `authorization_grant_types` varchar(1000) COLLATE utf8mb4_general_ci NOT NULL,
  `redirect_uris` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `post_logout_redirect_uris` varchar(1000) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT NULL,
  `scopes` varchar(1000) COLLATE utf8mb4_general_ci NOT NULL,
  `client_settings` varchar(2000) COLLATE utf8mb4_general_ci NOT NULL,
  `token_settings` varchar(2000) COLLATE utf8mb4_general_ci NOT NULL,
  `pasw_secret` varchar(255) COLLATE utf8mb4_general_ci DEFAULT NULL,
  `update_time` datetime DEFAULT NULL COMMENT '修改时间',
  `create_time` datetime DEFAULT NULL COMMENT '创建时间',
  `create_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '创建者',
  `update_by` varchar(64) CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci DEFAULT '' COMMENT '更新者',
  `create_dept` bigint DEFAULT NULL COMMENT '创建部门',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ----------------------------
-- Records of oauth2_registered_client
-- ----------------------------
BEGIN;
INSERT INTO `oauth2_registered_client` (`id`, `client_id`, `client_id_issued_at`, `client_secret`, `client_secret_expires_at`, `client_name`, `client_authentication_methods`, `authorization_grant_types`, `redirect_uris`, `post_logout_redirect_uris`, `scopes`, `client_settings`, `token_settings`, `pasw_secret`, `update_time`, `create_time`, `create_by`, `update_by`, `create_dept`) VALUES ('1', 'user-self', '2024-07-22 17:03:22', '$2a$10$xSno2Ohr9wPWDVAHuWRsEus6k89ACAx6hgdl8L0IeLB6GhQsTlds2', NULL, '1111', 'client_secret_basic', 'refresh_token,authorization_token,authorization_code,password', 'http://localhost:8080/thirdPartyLoginMe', NULL, 'openid,profile,message.read,message.write', '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.client.require-proof-key\":false,\"settings.client.require-authorization-consent\":false}', '{\"@class\":\"java.util.Collections$UnmodifiableMap\",\"settings.token.reuse-refresh-tokens\":true,\"settings.token.id-token-signature-algorithm\":[\"org.springframework.security.oauth2.jose.jws.SignatureAlgorithm\",\"RS256\"],\"settings.token.access-token-time-to-live\":[\"java.time.Duration\",300.000000000],\"settings.token.access-token-format\":{\"@class\":\"org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat\",\"value\":\"self-contained\"},\"settings.token.refresh-token-time-to-live\":[\"java.time.Duration\",3600.000000000],\"settings.token.authorization-code-time-to-live\":[\"java.time.Duration\",300.000000000],\"settings.token.device-code-time-to-live\":[\"java.time.Duration\",300.000000000]}', '123456', '2024-08-27 14:19:27', NULL, '', NULL, NULL);
COMMIT;

SET FOREIGN_KEY_CHECKS = 1;
