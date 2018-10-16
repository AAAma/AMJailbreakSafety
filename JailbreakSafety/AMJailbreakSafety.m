//
//  AMJailbreakSafety.m
//  JailbreakSafety
//
//  Created by Qz on 2018/10/16.
//  Copyright © 2018 Qz. All rights reserved.
//

#import "AMJailbreakSafety.h"

#import <mach-o/ldsyms.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>

/**
 * 获取动态库
 */
inline NSArray * am_dylibs(void) {
    NSMutableArray *tmpArr = [NSMutableArray array];
    for (uint32_t i = 0 ; i < _dyld_image_count(); ++i) {
        NSString *name = [[[NSString alloc]initWithUTF8String:_dyld_get_image_name(i)] lastPathComponent];
        if (name) {
            [tmpArr addObject:name];
        }
    }
    return tmpArr;
}

/**
 * 当一个进程被调试的时候，该进程会有一个标记来标记自己正在被调试
 * 通过sysctl去查看当前进程的信息
 */
inline BOOL am_dynamicTrace(void) {
    BOOL dy_debug = NO;
    
    struct kinfo_proc info;
    size_t info_size = sizeof(info);
    info.kp_proc.p_flag = 0;
    
    int name[4];
    name[0] = CTL_KERN;
    name[1] = KERN_PROC;
    name[2] = KERN_PROC_PID;
    name[3] = getpid();
    
    if ((sysctl(name, 4, &info, &info_size, NULL, 0) != -1) &&
        (info.kp_proc.p_flag & P_TRACED) != 0) {
        dy_debug = YES;
    }
    
    return dy_debug;
}

/**
 * AppStore's encryption
 * cryptid=1 加密状态
 * cryptid=0 解密状态
 */
inline BOOL am_encryption(void) {
    BOOL has_encryption = YES;
    const uint8_t *command = (const uint8_t *)(&_mh_execute_header + 1);
    for (uint32_t idx = 0; idx < _mh_execute_header.ncmds; idx++) {
        
#ifdef __LP64__
        if (((const struct load_command *)command)->cmd == LC_ENCRYPTION_INFO_64) {
            struct encryption_info_command_64 *crypt_cmd = (struct encryption_info_command_64 *)command;
            if (crypt_cmd->cryptid < 1) {
                has_encryption = NO;
            }
        }
#else
        if (((const struct load_command *)command)->cmd == LC_ENCRYPTION_INFO) {
            struct encryption_info_command *crypt_cmd = (struct encryption_info_command *)command;
            if (crypt_cmd->cryptid < 1) {
                has_encryption = NO;
            }
        }
#endif
        command += ((const struct load_command *)command)->cmdsize;
    }
    return has_encryption;
}

inline BOOL am_jailbreak(void) {
    BOOL is_jb_env = NO;
    BOOL is_jb_dir = NO;
    
    //检测系统越狱文件相关
    NSArray *pathArr = @[@"/Applications/Cydia.app",
                         @"/Library/MobileSubstrate/MobileSubstrate.dylib",
                         @"/bin/bash",
                         @"/usr/sbin/sshd",
                         @"/etc/apt"];
    for (NSString *path in pathArr) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            is_jb_dir = YES;
            break;
        }
    }
    
    //检测当前程序运行的环境变量
    //env != null -> 越狱设备
    if (getenv("DYLD_INSERT_LIBRARIES")) {
        is_jb_env = YES;
    }
    
    return (is_jb_env || is_jb_dir);
}

/**
 * 反动态调试， 为实现从用户态切换到内核态，系统提供了一个系统调用函数syscall
 * 26(SYS_ptrace)触发系统调用反追踪调试状态，31(PT_DENY_ATTACH)等为ptrace_ptr入参
 * syscall(26, 31, 0, 0, 0)
 * 此处使用汇编方式
 */
inline void am_ptrace(void) {
#ifdef __arm64__
    asm volatile(
                 "mov x0,#26\n"
                 "mov x1,#31\n"
                 "mov x2,#0\n"
                 "mov x3,#0\n"
                 "mov x16,#0\n"
                 "svc #128\n"
                 );
#endif
#ifdef __arm__
    asm volatile(
                 "mov r0,#31\n"
                 "mov r1,#0\n"
                 "mov r2,#0\n"
                 "mov r12,#26\n"
                 "svc #80\n"
                 );
#endif
}

static jmp_buf am_jmpBuf;
inline void am_exit(void) {
    longjmp(am_jmpBuf, 1);
}
