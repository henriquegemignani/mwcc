#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "compiler/MachineSimulation601.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/types.h"
#include "compiler/DWARF.h"
#include "compiler/MachineSimulation603.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"
#include <string.h>

/* Globals (generated from the original's .bss) */
SInt32 data_00582ff0;
SInt32 data_00582ff4;
SInt32 data_00582ff8;
SInt32 data_00582ffc;
FuncArg * data_00583000;
SInt32 data_00583004;
SInt32 data_00583008;
SInt32 data_0058300c;
SInt32 data_00583010;
SInt32 data_00583014;
/* Record used to index the seven-byte entries in DAT_00577661. */

Boolean is_execution_unit_seven(int instruction)
{
    return (int)data_00578340[((PCodeInstruction *)instruction)->opcode].executionUnit == 7;
}

void advance_instruction_pipeline(void)
{
    int i;

    for (i = 0; i < 6; i++) {
        if (data_00582fe8[i].instruction != NULL && data_00582fe8[i].count != 0) {
            data_00582fe8[i].count--;
        }
    }

    if (data_00582fe8[0].instruction != NULL && data_00582fe8[0].count == 0) {
        data_00582fe8[0].instruction = NULL;
    }
    if (data_00583008 != 0 && data_0058300c == 0) {
        data_00583008 = 0;
    }
    if (data_00583010 != 0 && data_00583014 == 0) {
        data_00583010 = 0;
    }
    if (data_00583000 != NULL && data_00583004 == 0 && data_00583008 == 0) {
        SInt32 v;
        FuncArg *arg;
        v = sclass_pipeline_table[(arg = data_00583000)->sclass * 6 + 3];
        data_00583008 = (SInt32)arg;
        data_0058300c = v;
        data_00583000 = NULL;
    }
    if (data_00582ff8 != 0 && data_00582ffc == 0 && data_00583000 == NULL) {
        SInt32 v;
        FuncArg *arg = (FuncArg *)data_00582ff8;
        v = sclass_pipeline_table[arg->sclass * 6 + 2];
        data_00583000 = arg;
        data_00583004 = v;
        data_00582ff8 = 0;
    }
    if (data_00582ff0 != 0 && data_00582ff4 == 0 && data_00582ff8 == 0) {
        SInt32 v;
        FuncArg *arg = (FuncArg *)data_00582ff0;
        v = sclass_pipeline_table[arg->sclass * 6 + 1];
        data_00582ff8 = (SInt32)arg;
        data_00582ffc = v;
        data_00582ff0 = 0;
    }
}

void set_execution_unit_instruction(PCodeInstruction *instruction)
{
    unsigned int entry;
    int offset;
    int value;

    offset = instruction->opcode;
    entry = data_00578340[offset].executionUnit;
    value = sclass_pipeline_table[offset * 6];
    if (entry == 7) {
        entry = 0;
    }
    data_00582fe8[entry].instruction = instruction;
    data_00582fe8[entry].count = value;
}

int is_execution_unit_available(PCodeInstruction *instruction)
{
    unsigned int kind;
    struct InstructionCountdown *counts;

    kind = data_00578340[instruction->opcode].executionUnit;
    if (kind == 7)
        kind = 0;
    counts = data_00582fe8;
    if (counts[kind].instruction != NULL)
        return 0;
    else
        return 1;
}

void clear_instruction_and_globals(void)
{
    data_00582fe8[0].instruction = NULL;
    data_00582ff0 = 0;
    data_00582ff8 = 0;
    data_00583000 = NULL;
    data_00583008 = 0;
    data_00583010 = 0;
}

SInt32 get_latency(PCodeInstruction *p)
{
    SInt32 n = data_00578340[p->opcode].latency;
    if (p->flags & fRecordBit) {
        n += 2;
    }
    if (p->opcode == 0x27 || p->opcode == 0x36) {
        n += p->operand_count - 2;
    }
    return n;
}
