#ifndef DRIVER_CLSTATICMAIN_H
#define DRIVER_CLSTATICMAIN_H

#include "compiler/common.h"
#include "compiler/win32.h"

#ifdef __cplusplus
extern "C" {
#endif

extern int register_callback(void (*fn)(void));
extern int callback_count;
extern void (*DAT_0057d018[])(void);
extern void exit(UINT exitCode);
extern void (*__stdio_exit)(void);
extern unsigned int __aborting;
extern void call_exit_callbacks_and_exit(UInt32 code);
extern SInt32 data_0057d21c;
extern SInt32 exit_callback;
extern int main(int a0, char **a1);
extern SInt32 data_0053600c;
extern SInt32 data_0053601c;
extern void free_argv_and_buffer(void);
extern void reset_args(void);
extern void _SetupArgs(void);
extern void _RunInit(void);
extern void abort_execution(void);
extern void fn_004025d0(void);
extern void invoke_function_pointer(void);
extern void call_function_pointer(void);
extern unsigned char __xc_a[];
extern char *argv_buffer;
extern void (*PTR_fn_00536350)(void);
extern void (*PTR_fn_00536354)(void);
extern char *data_00536258[];
extern char arg_whitespace[];

#ifdef __cplusplus
}
#endif

#endif
