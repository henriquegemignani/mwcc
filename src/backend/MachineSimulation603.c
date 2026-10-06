#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "compiler/MachineSimulation603.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/types.h"
#include "compiler/CExpr2.h"
#include "compiler/CTemplateNew.h"
#include "compiler/ConstantPropagation.h"
#include "compiler/DWARF.h"
#include "compiler/MachineSimulation601.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"
#include <string.h>

/* Globals (generated from the original's .bss) */
SInt32 pending_instruction_countdown[4/sizeof(SInt32)];
Object * data_00582ca8;
SInt32 data_00582cac;
SInt32 pending_instruction;
SInt32 data_00582cb4;
PCodeInstruction * data_00582cb8;
SInt32 data_00582cbc;
PCodeInstruction * data_00582cc0;
SInt32 data_00582cc4;
PCodeInstruction * data_00582cc8;
SInt32 data_00582ccc;
PCodeInstruction * data_00582cd0;
SInt32 data_00582cd4;
Object * data_00582cd8;
SInt32 data_00582cdc;
int data_00582ce0;
SInt32 pending_instruction_count;
UInt32 pending_instruction_retire_index;
unsigned int execution_unit_entry_index;
unsigned int DAT_00582cf4[4/sizeof(unsigned int)];
SInt32 data_00582cf8;
SInt32 data_00582d00;
SInt32 data_00582d08;
SInt32 data_00582d10;
int get_opcode_table_entry(PCodeInstruction *instruction)
{
    return opcode_table[instruction->opcode * 6];
}

static void RemovePending(const void *obj)
{
    SInt32 i;

    for (i = 0; i < 5 && data_00582cf0[i].entry != obj; i++)
        ;
    DAT_00582cf4[i * 2] = 1;
}

void retire_and_advance_pending_instructions(void)
{
    Object *obj0;
    SInt32 i;
    PCodeInstruction *o;

    i = 0;
    do {
        if (data_00582ca0[i].entry != NULL && pending_instruction_countdown[i * 2] != 0)
            --pending_instruction_countdown[i * 2];
        i = i + 1;
    } while (i < 8);

    if (pending_instruction_count != 0 && DAT_00582cf4[pending_instruction_retire_index * 2] != 0) {
        data_00582cf0[pending_instruction_retire_index].entry = NULL;
        pending_instruction_count = pending_instruction_count - 1;
        ++data_00582ce0;
        pending_instruction_retire_index = (pending_instruction_retire_index + 1U) % 5U;
        if (pending_instruction_count != 0 && DAT_00582cf4[pending_instruction_retire_index * 2] != 0) {
            data_00582cf0[pending_instruction_retire_index].entry = NULL;
            pending_instruction_count = pending_instruction_count - 1;
            data_00582ce0 = data_00582ce0 + 1;
            pending_instruction_retire_index = (pending_instruction_retire_index + 1U) % 5U;
        }
    }

    if (data_00582ca8 != NULL && data_00582cac == 0) {
        RemovePending(data_00582ca8);
        data_00582ca8 = NULL;
    }

    if (data_00582cb8 != NULL && data_00582cbc == 0) {
        RemovePending(data_00582cb8);
        data_00582cb8 = NULL;
    }

    if (data_00582cd0 != NULL && data_00582cd4 == 0) {
        RemovePending(data_00582cd0);
        data_00582cd0 = NULL;
    }

    if (data_00582cd8 != NULL && data_00582cdc == 0) {
        RemovePending(data_00582cd8);
        data_00582cd8 = NULL;
    }

    if (data_00582ca0[0].entry != NULL && pending_instruction_countdown[0] == 0) {
        RemovePending(data_00582ca0[0].entry);
        data_00582ca0[0].entry = NULL;
    }

    if ((o = data_00582cc0) != NULL && data_00582cc4 == 0 && (o->opcode == PC_FDIV || o->opcode == PC_FDIVS)) {
        RemovePending(data_00582cc0);
        data_00582cc0 = NULL;
    }

    if (data_00582cc8 != NULL && data_00582ccc == 0 && data_00582cd0 == NULL) {
        SInt32 v = 0;
        v = opcode_simulation_table[(o = data_00582cc8)->opcode * 6 + 2];
        data_00582cd0 = o;
        data_00582cd4 = v;
        data_00582cc8 = NULL;
    }

    if (data_00582cc0 != NULL && data_00582cc4 == 0 && data_00582cc8 == NULL) {
        SInt32 v = 0;
        v = opcode_simulation_table[(o = data_00582cc0)->opcode * 6 + 1];
        data_00582cc8 = o;
        data_00582ccc = v;
        data_00582cc0 = NULL;
    }

    if (pending_instruction != 0 && data_00582cb4 == 0 && data_00582cb8 == NULL) {
        SInt32 v = 0;
        PCodeInstruction *instruction = (PCodeInstruction *)pending_instruction;
        v = opcode_simulation_table[instruction->opcode * 6 + 1];
        data_00582cb8 = instruction;
        data_00582cbc = v;
        pending_instruction = 0;
    }
}

void assign_entry_to_execution_unit(short *entry)
{
    int category;
    int tableIndex;

    tableIndex = entry[10];
    category = machine_opcode_info[tableIndex].executionUnit;
    ++pending_instruction_count;
    --data_00582ce0;
    data_00582cf0[execution_unit_entry_index].value = (data_00582cf0[execution_unit_entry_index].entry = entry, 0);
    execution_unit_entry_index = (execution_unit_entry_index + 1) % 5;
    data_00582ca0[category].entry = entry;
    data_00582ca0[category].value = opcode_simulation_table[tableIndex * 6];
}

int fn_0052dfa0(PCodeInstruction *instruction)
{
    PCodeInstruction *previousInstruction;
    if (data_00582ce0 == 0) {
        return 0;
    }
    if (data_00582ca0[machine_opcode_info[instruction->opcode].executionUnit].entry != NULL) {
        return 0;
    }
    if ((instruction->flags & PCodeInstruction_ImplicitDefinition) != 0) {
        previousInstruction = data_00582cb8;
        if (previousInstruction != NULL && (previousInstruction->flags & PCodeInstruction_ImplicitDefinition) != 0) {
            return 0;
        }
    }
    return 1;
}

void fn_0052e000(void)
{
    data_00582ca0[0].entry = NULL;
    data_00582ca8 = NULL;
    pending_instruction = 0;
    data_00582cb8 = NULL;
    data_00582cc0 = NULL;
    data_00582cc8 = NULL;
    data_00582cd0 = NULL;
    data_00582cd8 = NULL;
    data_00582ce0 = 5;
    pending_instruction_count = 0;
    pending_instruction_retire_index = 0;
    execution_unit_entry_index = 0;
    data_00582cf0[0].entry = NULL;
    data_00582cf8 = 0;
    data_00582d00 = 0;
    data_00582d08 = 0;
    data_00582d10 = 0;
}

SInt32 get_adjusted_latency(PCodeInstruction *p)
{
    SInt32 n = machine_opcode_info[p->opcode].latency;
    if (p->flags & fRecordBit) {
        n += 2;
    }
    if (p->opcode == 0x27 || p->opcode == 0x36) {
        n += p->operand_count - 2;
    }
    return n;
}
