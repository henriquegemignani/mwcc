#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "driver/CLStaticMain.h"
#include "compiler/win32.h"
#include "driver/CLMain.h"
#include "driver/CLStaticPlugins.h"
#include "driver/CLToolExec.h"
#include "driver/ClientGlue.h"
#include "driver/ParserGlue-eabi-ppc-cc.h"
#include "driver/StaticParserGlue.h"
#include "msl/critical_regions_win32.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <msl_internal.h>

/* Globals (generated from the original's .bss) */
int callback_count;
SInt32 data_0057d21c;
char *argv_buffer;
char **argv;
SInt32 exit_callback;
#define EXIT_TABLE ((void (**)(void)) & data_0057d21c)
#pragma exceptions off
#pragma auto_inline off
int register_callback(void (*fn)(void))
{
    if (callback_count == 0x40)
        return -1;
    __begin_critical_region(0);
    DAT_0057d018[callback_count] = fn;
    callback_count = callback_count + 1;
    __end_critical_region(0);
    return 0;
}

#pragma auto_inline on
#pragma auto_inline off
void exit(UINT exitCode)
{
    if (__aborting == 0) {
        __begin_critical_region(0);
        while (callback_count > 0) {
            --callback_count;
            DAT_0057d018[callback_count]();
        }
        __end_critical_region(0);
        if (__stdio_exit != NULL) {
            __stdio_exit();
            __stdio_exit = NULL;
        }
    }
    call_exit_callbacks_and_exit(exitCode);
}
#pragma auto_inline reset

#pragma auto_inline reset
#pragma auto_inline reset
void call_exit_callbacks_and_exit(UInt32 exitCode)
{
    __begin_critical_region(0);
    while (data_0057d21c > 0) {
        data_0057d21c--;
        (*EXIT_TABLE[data_0057d21c - 64])();
    }
    __end_critical_region(0);
    delete_critical_sections();
    if (exit_callback != 0) {
        ((void (*)(void))exit_callback)();
        exit_callback = 0;
    }
    ExitProcess(exitCode);
}

#pragma exceptions reset

void free_argv_and_buffer(void)
{
    if (argv_buffer != NULL) {
        free(argv_buffer);
    }
    if ((argv != NULL) && (argc != 0)) {
        free(argv);
    }
}

#pragma auto_inline off
void reset_args(void)
{
    argv = data_00536258;
    argc = 0;
    return;
}
#pragma auto_inline reset

void _SetupArgs(void)
{
    char *p;
    char *q;
    int inquote;
    int numchars;
    int n;

    numchars = 1;
    argc = 0;
    argv = (char **)malloc(4);
    if (argv == NULL) {
        reset_args();
        return;
    }
    p = GetCommandLineA();
    q = argv_buffer = (char *)malloc(strlen(p) + 1);
    if (q == NULL) {
        reset_args();
        return;
    }
    while (strchr(arg_whitespace, *p) != NULL)
        p++;
    while (*p != 0) {
        if (argc + 1 >= numchars) {
            char **newargv;
            numchars += 16;
            newargv = (char **)realloc(argv, numchars * 4u);
            if (newargv == NULL)
                break;
            argv = newargv;
        }
        n = argc;
        argv[n] = q;
        argc++;
        (void)n;
        inquote = 0;
        while (*p != 0) {
            if (!inquote && strchr(arg_whitespace, *p) != NULL) {
                p++;
                while (*p != 0 && strchr(arg_whitespace, *p) != NULL)
                    p++;
                *q++ = 0;
                break;
            }
            if (*p == '"') {
                p++;
                inquote = !inquote;
            } else if (*p == '\\' && p[1] == '"') {
                *q++ = '"';
                p += 2;
            } else {
                *q++ = *p++;
            }
        }
    }
    *q = 0;
    argv[argc] = NULL;
    register_callback(free_argv_and_buffer);
}

void _RunInit(void)
{
    void (**initializer)(void);

    for (initializer = (void (**)(void))&DAT_0057b004; *initializer != NULL; ++initializer) {
        (*initializer)();
    }
    register_callback(__destroy_global_chain);
}

#pragma exceptions off
int main(int argc, char **argv)
{
    SInt32 primaryToolIdentifier, secondaryToolIdentifier;
    SInt32 primaryPluginIdentifier, secondaryPluginIdentifier;
    SInt32 result;

    if (ClientGlue_SetNamesAndRun(argc, argv, data_0053601c, data_0053600c) != 0)
        exit(1);

    if (!fn_0040535e() || !fn_004053f0()) {
        fprintf(stderr, "\r\nFATAL ERROR:  Could not initialize resource strings\r\n");
        exit(1);
    }

    if (!fn_0040534e() || !fn_004053d0()) {
        fprintf(stderr, "\r\nFATAL ERROR:  Could not initialize built-in plugins\r\n");
        exit(1);
    }

    if (!fn_00405840()) {
        fprintf(stderr, "\r\nFATAL ERROR:  Could not initialize options\r\n");
        exit(1);
    }

    CLStaticPlugins_SetIdentifiers(&primaryPluginIdentifier, &secondaryPluginIdentifier);
    fn_004052a0(primaryPluginIdentifier, secondaryPluginIdentifier);
    fn_004053a0(&primaryToolIdentifier, &secondaryToolIdentifier);
    fn_004052d0(primaryToolIdentifier, secondaryToolIdentifier);
    fn_004053c0(&primaryToolIdentifier);
    fn_004052c0(primaryToolIdentifier);

    result = ClientGlue_InitializeAndParseCommandLine();
    if (result != 0) {
        if (result == 2)
            fprintf(stderr, "\r\nUser break, cancelled...\r\n");
        else
            fprintf(stderr, "\r\nErrors caused tool to abort.\r\n");
    }
    fn_00405340(result);
    exit(result);
    return 0;
}
#pragma exceptions reset

void abort_execution(void)

{
    abort();
    return;
}

void fn_004025d0(void)

{
    invoke_function_pointer();
    return;
}

void invoke_function_pointer(void)

{
    PTR_fn_00536350();
    return;
}

void call_function_pointer(void)

{
    PTR_fn_00536354();
    return;
}
