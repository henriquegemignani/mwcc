#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "compiler/MachineSimulation750.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/types.h"
#include "compiler/ConstantPropagation.h"
#include "compiler/DWARF.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"
#include "compiler/Scheduler.h"

/* Globals (generated from the original's .bss) */
PoolEntry data_00582e70[9];
struct PCodeInstruction * data_00582e78;
SInt32 data_00582e7c;
struct PCodeInstruction * data_00582e80;
SInt32 data_00582e84;
struct PCodeInstruction * DAT_00582e88;
SInt32 data_00582e8c;
struct PCodeInstruction * data_00582e90;
SInt32 data_00582e94;
struct PCodeInstruction * DAT_00582e98;
SInt32 data_00582e9c;
struct PCodeInstruction * DAT_00582ea0;
SInt32 data_00582ea4;
struct PCodeInstruction * DAT_00582ea8;
SInt32 data_00582eac;
struct PCodeInstruction * data_00582eb0;
SInt32 data_00582eb4;
struct PCodeInstruction * data_00582eb8;
struct PCodeInstruction * data_00582ebc;
int data_00582ec0;
SInt32 pending_opt_args;
UInt32 simulation_pipeline_index;
UInt32 opt_arg_index;
OptPair DAT_00582ed0[6];
unsigned int DAT_00582ed8;
unsigned int DAT_00582ee0;
unsigned int DAT_00582ee8;
unsigned int _DAT_00582ef0;
unsigned int _DAT_00582ef8;
int get_opcode_table_first_entry(PCodeInstruction *instruction)
{
    return opcode_table_entries[instruction->opcode * 6];
}

void advance_simulation_pipeline(void)
{
    SInt32 i;
    SInt32 v;

    data_00582eb8 = NULL;
    data_00582ebc = NULL;
    i = 0;
    do {
        if (data_00582e70[i].obj != NULL && data_00582e70[i].cnt != 0)
            data_00582e70[i].cnt--;
        i++;
    } while (i < 9);
    if (pending_opt_args != 0 && DAT_00582ed0[simulation_pipeline_index].completed != 0) {
        DAT_00582ed0[simulation_pipeline_index].instruction = NULL;
        pending_opt_args--;
        data_00582ec0++;
        simulation_pipeline_index = (simulation_pipeline_index + 1) % 6;
        if (pending_opt_args != 0 && DAT_00582ed0[simulation_pipeline_index].completed != 0) {
            DAT_00582ed0[simulation_pipeline_index].instruction = NULL;
            pending_opt_args--;
            data_00582ec0++;
            simulation_pipeline_index = (simulation_pipeline_index + 1) % 6;
        }
    }
    if (data_00582e78 != NULL && data_00582e7c == 0) {
        SInt32 j;
        PCodeInstruction *q;
        q = data_00582e78;
        for (j = 0; j < 6 && DAT_00582ed0[j].instruction != q; j++)
            ;
        DAT_00582ed0[j].completed = 1;
        data_00582e78 = NULL;
        data_00582eb8 = q;
    }
    if (data_00582e90 != NULL && data_00582e94 == 0) {
        SInt32 j;
        PCodeInstruction *q;
        q = data_00582e90;
        for (j = 0; j < 6 && DAT_00582ed0[j].instruction != q; j++)
            ;
        DAT_00582ed0[j].completed = 1;
        data_00582e90 = NULL;
    }
    if (DAT_00582ea8 != NULL && data_00582eac == 0) {
        SInt32 j;
        PCodeInstruction *q;
        q = DAT_00582ea8;
        for (j = 0; j < 6 && DAT_00582ed0[j].instruction != q; j++)
            ;
        DAT_00582ed0[j].completed = 1;
        DAT_00582ea8 = NULL;
    }
    if (data_00582eb0 != NULL && data_00582eb4 == 0) {
        SInt32 j;
        PCodeInstruction *q;
        q = data_00582eb0;
        for (j = 0; j < 6 && DAT_00582ed0[j].instruction != q; j++)
            ;
        DAT_00582ed0[j].completed = 1;
        data_00582eb0 = NULL;
    }
    if (data_00582e70[0].obj != NULL && data_00582e70[0].cnt == 0) {
        SInt32 j;
        PCodeInstruction *q;
        q = data_00582e70[0].obj;
        for (j = 0; j < 6 && DAT_00582ed0[j].instruction != q; j++)
            ;
        DAT_00582ed0[j].completed = 1;
        data_00582e70[0].obj = NULL;
    }
    if (data_00582e80 != NULL && data_00582e84 == 0) {
        SInt32 j;
        PCodeInstruction *q;
        q = data_00582e80;
        for (j = 0; j < 6 && DAT_00582ed0[j].instruction != q; j++)
            ;
        DAT_00582ed0[j].completed = 1;
        data_00582e80 = NULL;
        data_00582ebc = q;
    }
    {
        PCodeInstruction *p;
        SInt32 j;
        PCodeInstruction *q;
        SInt16 tag;
        if ((p = DAT_00582e98) != NULL && data_00582e9c == 0 && ((tag = p->opcode) == 0xa8 || tag == 0xa9)) {
            q = DAT_00582e98;
            for (j = 0; j < 6 && DAT_00582ed0[j].instruction != q; j++)
                ;
            DAT_00582ed0[j].completed = 1;
            DAT_00582e98 = NULL;
        }
    }
    if (DAT_00582ea0 != NULL && data_00582ea4 == 0 && DAT_00582ea8 == NULL) {
        SInt32 v;
        PCodeInstruction *q;
        v = data_00576f28[(q = DAT_00582ea0)->opcode].latency4;
        DAT_00582ea8 = q;
        data_00582eac = v;
        DAT_00582ea0 = NULL;
    }
    if (DAT_00582e98 != NULL && data_00582e9c == 0 && DAT_00582ea0 == NULL) {
        SInt32 v;
        PCodeInstruction *q;
        v = data_00576f28[(q = DAT_00582e98)->opcode].latency3;
        DAT_00582ea0 = q;
        data_00582ea4 = v;
        DAT_00582e98 = NULL;
    }
    if (DAT_00582e88 != NULL && data_00582e8c == 0 && data_00582e90 == NULL) {
        SInt32 v;
        PCodeInstruction *q;
        v = data_00576f28[(q = DAT_00582e88)->opcode].latency3;
        data_00582e90 = q;
        data_00582e94 = v;
        DAT_00582e88 = NULL;
    }
}

static inline void record_opt_arg(PCodeInstruction *p)
{
    pending_opt_args++;
    data_00582ec0--;
    DAT_00582ed0[opt_arg_index].instruction = p;
    DAT_00582ed0[opt_arg_index].completed = 0;
    opt_arg_index = (opt_arg_index + 1) % 6;
}

void record_instruction_kind(PCodeInstruction *p)
{
    SInt32 kind, value;

    kind = DAT_00576f29[p->opcode - 1].kind;
    value = opcode_table_entries[p->opcode * 6 - 3];
    record_opt_arg(p);
    if (kind == 2 && data_00582e78 == NULL)
        kind = 1;
    data_00582e70[kind].obj = p;
    data_00582e70[kind].cnt = value;
}

/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
int fn_0052f120(struct PCodeInstruction *instruction)
{
    int kind;
    PCodeInstruction *register1;
    unsigned int register1Absent;
    int register2Absent;
    int firstAbsent;
    PCodeInstruction *register2;
    struct PCodeInstruction *other;
    if (data_00582ec0 == 0)
        return 0;
    kind = data_00576f28[instruction->opcode].kind;
    if (kind == 2) {
        firstAbsent = 0;
        if ((register1 = data_00582e78) == NULL)
            firstAbsent = 1;
        register1Absent = firstAbsent;
        register2Absent = 0;
        if ((register2 = data_00582e80) == NULL)
            register2Absent = 1;
        if (firstAbsent == 0 && register2Absent == 0)
            return 0;
        if (register1Absent != 0 && register2Absent != 0)
            return 1;
        if (register1Absent != 0)
            register1 = register2;
        if (Scheduler_ReturnZero(instruction, register1, 0) != 0)
            return 0;
        if (Scheduler_ReturnZero(instruction, data_00582eb8, 0) != 0)
            return 0;
        if (Scheduler_ReturnZero(instruction, data_00582ebc, 0) != 0)
            return 0;
    } else if (data_00582e70[kind].obj != NULL)
        return 0;
    if ((instruction->flags & PCodeInstruction_ImplicitDefinition) != 0 && (other = data_00582e90) != NULL &&
        (other->flags & PCodeInstruction_ImplicitDefinition) != 0)
        return 0;
    return 1;
}

void reset_simulation_pipeline(void)
{
    int stage;

    for (stage = 0; stage < 9; ++stage) {
        data_00582e70[stage].obj = NULL;
    }
    data_00582ec0 = 6;
    pending_opt_args = 0;
    simulation_pipeline_index = 0;
    opt_arg_index = 0;
    DAT_00582ed0[0].instruction = NULL;
    DAT_00582ed8 = 0;
    DAT_00582ee0 = 0;
    DAT_00582ee8 = 0;
    _DAT_00582ef0 = 0;
    _DAT_00582ef8 = 0;
    data_00582eb8 = NULL;
    data_00582ebc = NULL;
}

int fn_0052f330(PCodeInstruction *instruction)
{
    int count;
    unsigned int flags;

    flags = instruction->flags;
    count = DAT_00576f29[instruction->opcode].count;
    if ((flags & PCodeInstruction_CloneExtraOperandExcluded) != 0) {
        count += 2;
    }
    if ((instruction->opcode == PC_LMW) || (instruction->opcode == PC_STMW)) {
        count += instruction->operand_count - 2;
    }
    return count;
}
