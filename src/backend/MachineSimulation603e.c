#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "compiler/MachineSimulation603e.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/types.h"
#include "compiler/CTemplateNew.h"
#include "compiler/DWARF.h"
#include "compiler/MachineSimulation601.h"
#include "compiler/MachineSimulation603.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"
#include "compiler/Scheduler.h"
/* Six-byte table records at 0x576418; the length byte is at +1. */

#include <string.h>

/* Globals (generated from the original's .bss) */
struct InstructionTimingSlot instruction_timing_slots[8];
int opcodeValues[4/sizeof(int)];
struct PCodeInstruction * data_00582d20;
int data_00582d24;
struct PCodeInstruction * data_00582d28;
int data_00582d2c;
struct PCodeInstruction * data_00582d30;
int data_00582d34;
struct PCodeInstruction * data_00582d38;
int data_00582d3c;
struct PCodeInstruction * queuedInstruction;
int data_00582d44;
struct PCodeInstruction * data_00582d48;
int data_00582d4c;
struct PCodeInstruction * data_00582d50;
int data_00582d54;
int DAT_00582d58;
int DAT_00582d5c;
unsigned int data_00582d60;
unsigned int data_00582d64;
InstructionCompletionEntry instruction_completion_entries[5];
unsigned int data_00582d6c[4/sizeof(unsigned int)];
SInt32 data_00582d70;
SInt32 data_00582d78;
SInt32 data_00582d80;
SInt32 data_00582d88;

int get_instruction_opcode_table_value(PCodeInstruction *instruction)
{
    return instruction_opcode_table[instruction->opcode * 6];
}

void fn_0052e110(void)
{
    int slot;
    int index20;
    int index30;
    int index48;
    int index50;
    int index18;
    struct PCodeInstruction *instruction;
    int index38;
    short opcode;
    struct PCodeInstruction *pending38;
    int cycles28;
    struct PCodeInstruction *pending48;
    struct PCodeInstruction *pending20;
    struct PCodeInstruction *pending50;
    struct PCodeInstruction *pending30;
    int cycles40;
    int cycles38;
    struct PCodeInstruction *queued;
    struct PCodeInstruction *queued28;
    slot = 0;
    do {
        if (instruction_timing_slots[slot].instruction != NULL && instruction_timing_slots[slot].cycles != 0)
            instruction_timing_slots[slot].cycles -= 1;
        slot++;
    } while (slot < 8);
    if (DAT_00582d5c != 0 && instruction_completion_entries[data_00582d60].completed != 0) {
        instruction_completion_entries[data_00582d60].instruction = NULL;
        DAT_00582d5c -= 1;
        DAT_00582d58 += 1;
        data_00582d60 = (data_00582d60 + 1) % 5;
        if (DAT_00582d5c != 0 && instruction_completion_entries[data_00582d60].completed != 0) {
            instruction_completion_entries[data_00582d60].instruction = NULL;
            DAT_00582d5c -= 1;
            DAT_00582d58 += 1;
            data_00582d60 = (data_00582d60 + 1) % 5;
        }
    }
    if (data_00582d20 != NULL && data_00582d24 == 0) {
        pending20 = data_00582d20;
        index20 = 0;
        while (index20 < 5 && instruction_completion_entries[index20].instruction != pending20) {
            index20 = index20 + 1;
        }
        instruction_completion_entries[index20].completed = 1;
        data_00582d20 = NULL;
    }
    if (data_00582d30 != NULL && data_00582d34 == 0) {
        pending30 = data_00582d30;
        index30 = 0;
        while (index30 < 5 && instruction_completion_entries[index30].instruction != pending30) {
            index30 = index30 + 1;
        }
        instruction_completion_entries[index30].completed = 1;
        data_00582d30 = NULL;
    }
    if (data_00582d48 != NULL && data_00582d4c == 0) {
        pending48 = data_00582d48;
        index48 = 0;
        while (index48 < 5 && instruction_completion_entries[index48].instruction != pending48) {
            index48 = index48 + 1;
        }
        instruction_completion_entries[index48].completed = 1;
        data_00582d48 = NULL;
    }
    if (data_00582d50 != NULL && data_00582d54 == 0) {
        pending50 = data_00582d50;
        index50 = 0;
        while (index50 < 5 && instruction_completion_entries[index50].instruction != pending50) {
            index50 = index50 + 1;
        }
        instruction_completion_entries[index50].completed = 1;
        data_00582d50 = NULL;
    }
    if (instruction_timing_slots[0].instruction != NULL && opcodeValues[0] == 0) {
        struct PCodeInstruction *pending18 = instruction_timing_slots[0].instruction;
        index18 = 0;
        while (index18 < 5 && instruction_completion_entries[index18].instruction != pending18)
            index18++;
        instruction_completion_entries[index18].completed = 1;
        instruction_timing_slots[0].instruction = NULL;
    }
    instruction = data_00582d38;
    if (instruction != NULL && data_00582d3c == 0 && ((opcode = instruction->opcode) == 168 || opcode == 169)) {
        pending38 = data_00582d38;
        index38 = 0;
        while (index38 < 5 && instruction_completion_entries[index38].instruction != pending38) {
            index38 = index38 + 1;
        }
        instruction_completion_entries[index38].completed = 1;
        data_00582d38 = NULL;
    }
    if (queuedInstruction != NULL && data_00582d44 == 0 && data_00582d48 == NULL) {
        cycles40 = data_005758a4[(queued = queuedInstruction)->opcode][0];
        data_00582d48 = queued;
        data_00582d4c = cycles40;
        queuedInstruction = NULL;
    }
    if (data_00582d38 != NULL && data_00582d3c == 0 && queuedInstruction == NULL) {
        cycles38 = opcode_cycles[(queued = data_00582d38)->opcode][0];
        queuedInstruction = queued;
        data_00582d44 = cycles38;
        data_00582d38 = NULL;
    }
    if (data_00582d28 != NULL && data_00582d2c == 0 && data_00582d30 == NULL) {
        cycles28 = opcode_cycles[(queued28 = data_00582d28)->opcode][0];
        data_00582d30 = queued28;
        data_00582d34 = cycles28;
        data_00582d28 = NULL;
    }
}

void fn_0052e450(struct PCodeInstruction *instruction)
{
    unsigned int kind;
    int opcodeIndex;
    int opcodeValue;

    opcodeIndex = instruction->opcode;
    kind = machineOpcodeInfo[opcodeIndex].executionUnit;
    opcodeValue = DAT_005758a2[opcodeIndex * 6];
    if ((kind == 1) && (data_00582d20 != NULL)) {
        kind = 7;
    }
    DAT_00582d5c++;
    DAT_00582d58--;
    instruction_completion_entries[data_00582d64].instruction = instruction, data_00582d6c[data_00582d64 * 2] = 0;
    data_00582d64 = (data_00582d64 + 1) % 5;
    instruction_timing_slots[kind].instruction = instruction;
    opcodeValues[kind * 2] = opcodeValue;
}

int is_instruction_issuable(PCodeInstruction *instr)
{
    UInt32 unit;
    PCodeInstruction *list;
    PCodeInstruction *ref;

    if (!DAT_00582d58)
        return 0;
    unit = machineOpcodeInfo[instr->opcode].executionUnit;
    if (instruction_timing_slots[unit].instruction) {
        if (unit == 1) {
            switch (instr->opcode) {
                case PC_ADD:
                case PC_ADDC:
                case PC_ADDI:
                case PC_ADDIS:
                case PC_CMPI:
                case PC_CMP:
                case PC_CMPLI:
                case PC_CMPL:
                    list = instr;
                    ref = data_00582d20;
                    if (Scheduler_ReturnZero(list, ref, 0))
                        return 0;
                    if (!data_00582d50)
                        return 1;
                    break;
            }
        }
        return 0;
    }
    if ((instr->flags & fIsWrite) && instruction_timing_slots[3].instruction &&
        (instruction_timing_slots[3].instruction->flags & fIsWrite))
        return 0;
    return 1;
}

static inline void set_counter(unsigned char *storage, unsigned int value)
{
    unsigned int *counter = (unsigned int *)storage;
    *counter = value;
}

void fn_0052e590(void)
{
    instruction_timing_slots[0].instruction = NULL;
    data_00582d20 = NULL;
    data_00582d28 = NULL;
    data_00582d30 = NULL;
    data_00582d38 = NULL;
    queuedInstruction = NULL;
    data_00582d48 = NULL;
    data_00582d50 = NULL;
    DAT_00582d58 = 5;
    DAT_00582d5c = 0;
    data_00582d60 = 0;
    data_00582d64 = 0;
    instruction_completion_entries[0].instruction = NULL;
    data_00582d70 = 0;
    data_00582d78 = 0;
    data_00582d80 = 0;
    data_00582d88 = 0;
}

SInt32 fn_0052e640(PCodeInstruction *p)
{
    SInt32 n = machineOpcodeInfo[p->opcode].latency;
    if (p->flags & fRecordBit) {
        n += 2;
    }
    if (p->opcode == 0x27 || p->opcode == 0x36) {
        n += p->operand_count - 2;
    }
    return n;
}
