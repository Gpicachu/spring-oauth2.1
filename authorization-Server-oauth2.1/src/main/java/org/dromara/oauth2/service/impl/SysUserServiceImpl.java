package org.dromara.oauth2.service.impl;//package org.dromara.oauth2.service.impl;
//
//import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
//import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
//import org.oauth.server.mapper.SysUserMapper;
//import org.oauth.server.model.SysUserEntity;
//import org.oauth.server.service.SysUserService;
//import org.springframework.stereotype.Service;
//
///**
// * @author Rommel
// * @version 1.0
// * @date 2023/7/12-18:30
// * @description TODO
// */
//@Service
//public class SysUserServiceImpl extends ServiceImpl<SysUserMapper, SysUserEntity> implements SysUserService {
//
//
//    @Override
//    public SysUserEntity selectByUsername(String username) {
//        LambdaQueryWrapper<SysUserEntity> lambdaQueryWrapper = new LambdaQueryWrapper();
//        lambdaQueryWrapper.eq(SysUserEntity::getUsername,username);
//        return this.getOne(lambdaQueryWrapper);
//    }
//
//
//}
