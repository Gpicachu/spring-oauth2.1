# Spring oauth2 authorization server示例项目

## 项目说明

Spring OAuth2 Authorization Server集成与拓展项目，包括认证服务搭建、三方登录对接、自定义grant_type方式获取token、前后端分离实现，客户端、资源服务、前端单体项目对接认证服务实现等。

## 项目支持的授权方式

授权码模式

password模式

自定义Token模式

## 项目环境要求

**Java版本大于等于17**

**Springboot版本大于等于3.1.0-RC1**

**IDE安装Lombok插件**

## 仓库内项目结构

```
spring-oauth2.1 # 最外层目录
 │  README.md # 项目描述文件
 │  
 ├─authorization-Server-oauth2.1 # 认证服务器
 │  
 └─gateway-example # 网关集成OAuth2认证服务示例
     │  
     ├─gateway-client-example # 网关
     │  
     ├─normal-resource-example # webmvc资源服务
     │  
     ├─webflux-resource-example # webflux资源服务
     │  
     └─pom.xml # 公共依赖，依赖管理
 └─pom.xml # 公共依赖，依赖管理     
```