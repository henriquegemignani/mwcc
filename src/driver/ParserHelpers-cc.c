#include "compiler/common.h"
#include "driver/ParserHelpers-cc.h"
#include "driver/CLIO.h"
#include "driver/CWParserPluginsPrivate.h"
#include "driver/CWPluginsPrivate.h"
#include "driver/Files.h"
#include "driver/MacSpecs.h"
#include "driver/Memory.h"
#include "driver/MsDos.h"
#include "driver/Option.h"
#include "driver/Parameter.h"
#include "driver/ParserGlue-eabi-ppc-cc.h"
#include "driver/ParserHelpers.h"
#include "driver/Targets.h"
#include "driver/ToolHelpers-cc.h"
#include "driver/ToolHelpers.h"
#include <stdio.h>
#include <setjmp.h>
#include <string.h>
#include "driver/CLDropinCallbacks_V10.h"

/* Globals (generated from the original's .bss) */
struct CWPluginPrivateContext * pluginPrivateContext;
char data_00587d04[256/sizeof(char)];
int data_00587e14;
Boolean output_path_set;
unsigned char data_00588530;
#define OPTION_ASSERT(cond, line) ((cond) ? (void)0 : CLIO_ReportAssertionFailure(#cond, "ParserHelpers-cc.c", line))
#define PR_UNSET 0
int append_undef_directive(char *option, int unused, char *symbol)
{
    char buf[300];
    if (driverTool[1] == 0x632b2b20 || driverTool[1] == 0x41736d20)
        sprintf(buf, "#undef %s\n", symbol);
    else if (driverTool[1] == 0x70617363)
        sprintf(buf, "{$undefc %s}\n", symbol);
    else {
        sprintf(buf, "Option -%s is not supported with this plugin", option);
        fn_0040ecb1(0x1c, buf);
        return 0;
    }
    ParserHelpers_AppendText(&directive_storage, buf);
    return 1;
}

int append_include_directive(char *option, void *handle, char *filename)
{
    char buf[300];
    struct StorageHandle **storage;
    if (!handle)
        storage = &directive_storage;
    else
        storage = (struct StorageHandle **)handle;
    if (*filename) {
        if (driverTool[1] == 0x632b2b20 || driverTool[1] == 0x41736d20)
            sprintf(buf, "#include \"%s\"\n", filename);
        else if (driverTool[1] == 0x70617363)
            sprintf(buf, "{$I+}\n{$I %s}\n{$I-}\n", filename);
        else {
            sprintf(buf, "Option -%s is not supported with this plugin", option);
            fn_0040ecb1(0x1c, buf);
            return 0;
        }
        ParserHelpers_AppendText(storage, buf);
    }
    return 1;
}

static inline int PragmaHasSetting(const Pragma *pragma, char setting)
{
    const char *value = pragma->value;
    return *value == setting;
}

int ParserHelpers_cc_EmitPragmas(Pragma *pragmas)
{
    char buf[300];
    for (; pragmas->pragma; pragmas++) {
        if (pragmas->flags == 0 || pragmas->flags == 1) {
            const char *value = NULL;
            Boolean reverse = pragmas->flags == 1;
            char on = !reverse ? (char)1 : (char)2;
            char off = !reverse ? (char)2 : (char)1;
            if (PragmaHasSetting(pragmas, on))
                value = "on";
            else if (PragmaHasSetting(pragmas, off))
                value = "off";
            else if (PragmaHasSetting(pragmas, 3))
                value = "auto";
            else if (PragmaHasSetting(pragmas, 4))
                value = "reset";
            else
                OPTION_ASSERT(*((char *)pragmas->value) == PR_UNSET, 181);
            if (value) {
                sprintf(buf, "#pragma %s %s\n", pragmas->pragma, value);
                ParserHelpers_AppendText(&directive_storage, buf);
            }
        } else {
            OPTION_ASSERT(!"Can't handle pragma", 190);
        }
    }
    return 1;
}

int set_output_path(char *name, int unused, char *path)
{
    OSSpec spec1;
    Boolean isdir1;
    OSSpec spec2;
    Boolean isdir2;
    CWFileSpec info;
    long count;
    ExportedRecord tinfo;
    int err;
    if (!path)
        path = name;
    if (DAT_00537762 == 3 || (DAT_00537762 == 0 && driverTool[0] == 0x4c696e6b)) {
        if (data_0058851d) {
            fn_0040ecb1(0x29, path);
            return 0;
        }
        data_0058851d = 1U;
        if (driverTool[0] == 0x436f6d70) {
            strncpy(&output_path, path, 0x100);
            return 1;
        }
        if ((err = make_osspec_from_path(path, &spec2, &isdir2)) != 0) {
            Targets_ReportOperatingSystemError(0x40, err, path);
            return 0;
        }
        if (isdir2)
            MsDos_CopyStringToBuffer(spec2.name, &output_path, 0x104);
        ToolHelpers_cc_CallFileInfoForDirectory(&spec2);
        return 1;
    }
    if ((err = make_osspec_from_path(path, &spec1, &isdir1)) != 0) {
        Targets_ReportOperatingSystemError(0x40, err, path);
        return 0;
    }
    if (!err && !isdir1) {
        if (output_path_set) {
            fn_0040ecb1(0x3b, path);
            return 0;
        }
        output_path_set = 1;
        MacSpecs_MakeCWFileSpecFromString((char *)&spec1, &info);
        if ((err = CWParserPluginsPrivate_CallFileInfo(pluginPrivateContext, &info)) != 0) {
            DAT_00543380 = "CWParserSetOutputFileDirectory";
            longjmp(plugin_request_jmp_buf, err);
        }
        return 1;
    } else {
        if (data_00587d04[0]) {
            fn_0040ecb1(0x29, path);
            return 0;
        }
        strncpy(data_00587d04, path, 0x100);
        if (data_00537764 == 8)
            return 1;
        if (data_00588530 > 1)
            return 1;
        CWPluginsPrivate_GetNumFiles(pluginPrivateContext, &count);
        while (count-- > 0) {
            if (!CWPluginsPrivate_InvokeExportedRecordCallback(pluginPrivateContext, count, 0, &tinfo) &&
                tinfo.fileType == 0x54455854) {
                data_00588530 = 1;
                break;
            }
        }
        if (!data_00588530) {
            data_00588530 = 2;
            return 1;
        }
        ToolHelpers_cc_SetFileOutputName(count, data_0054a0b8, data_00587d04);
        data_00587d04[0] = 0;
        return 1;
    }
}

int log_linker_option(const char *option)
{
    Targets_ForwardVarArgsAndLongjmp("Calling linker option '%s'\n", option);
    return 0;
}

void fn_0040d822(void)
{
    if (data_00587d04[0]) {
        int n = ToolHelpers_cc_GetNumFiles();
        if (data_00537764 == 8)
            strcpy(data_00537848, data_00587d04);
        else if (data_00588530 == 2) {
            if (data_00587e10 > 0 || data_00587e14 > 0)
                fn_0040ecb1(0x29, data_00587d04);
            else
                fn_0040ecb1(0x2a, data_00587d04);
        } else
            ToolHelpers_cc_SetFileOutputName(n - 1, data_0054a0b8, data_00587d04);
        data_00587d04[0] = 0;
    }
    if (output_path_set) {
        data_00537845 = 0;
    }
}
