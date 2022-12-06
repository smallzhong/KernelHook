#pragma once

#define Mod_M       0xc0
#define RM_M        0x7
#define Base_M      0x7
#define REX_W       0x8

#define MAX_INSN_LEN_x86    15
#define MAX_INSN_LEN_x86_32 MAX_INSN_LEN_x86
#define MAX_INSN_LEN_x86_64 MAX_INSN_LEN_x86

enum __bits { __b16, __b32, __b64 };

#ifdef __i386__
#define insn_len(insn)  insn_len_x86_32(insn)
#define MAX_INSN_LEN    MAX_INSN_LEN_x86_32
#elif defined(__x86_64__)
#define insn_len(insn)  insn_len_x86_64(insn)
#define MAX_INSN_LEN    MAX_INSN_LEN_x86_64
#endif

/*==============================================================================*/
/*                            获取32位指令长度                                  */
/*==============================================================================*/
int insn_len_x86_32(void *insn);

/*==============================================================================*/
/*                            获取64位指令长度                                  */
/*==============================================================================*/
int insn_len_x86_64(void *insn);
