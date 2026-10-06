#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "compiler/MachineSimulation604.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/types.h"
#include "compiler/DWARF.h"
#include "compiler/MachineSimulation601.h"
#include "compiler/MachineSimulation603.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"
#include "compiler/Scheduler.h"

/* Globals (generated from the original's .bss) */
InstructionValueEntry execution_unit_instructions[9];
PCodeInstruction * data_00582d98;
PCodeInstruction * data_00582da0;
FuncArg * data_00582da8;
SInt32 data_00582db0;
PCodeInstruction * data_00582db8;
SInt32 data_00582dc0;
PCodeInstruction * data_00582dc8;
SInt32 data_00582dd0;
PCodeInstruction * data_00582dd8;
PCodeInstruction * data_00582ddc;
int data_00582de0;
SInt32 DAT_00582de4;
SInt32 instruction_retire_index;
unsigned int next_instruction_slot;
InstructionValueEntry instruction_ring[16];
/* Six-byte table records at 0x576418; the length byte is at +1. */

int get_opcode_table_value(PCodeInstruction *instruction)
{
    return opcode_table_values[instruction->opcode * 6];
}

void advance_instruction_stages_and_retire(void)
{
    SInt32 count;
    SInt32 slotIndex;
    SInt32 retiredCount;

    data_00582dd8 = NULL;
    data_00582ddc = NULL;

    slotIndex = 0;
    do {
        if (execution_unit_instructions[slotIndex].instruction != NULL &&
            execution_unit_instructions[slotIndex].value != 0)
            execution_unit_instructions[slotIndex].value--;
        slotIndex++;
    } while (slotIndex < 9);

    retiredCount = 0;
    do {
        if (DAT_00582de4 == 0)
            break;
        if (instruction_ring[instruction_retire_index].value == 0)
            break;
        instruction_ring[instruction_retire_index].instruction = NULL;
        DAT_00582de4--;
        data_00582de0++;
        instruction_retire_index = (instruction_retire_index + 1) & 0xF;
        retiredCount++;
    } while (retiredCount < 5);

    if (execution_unit_instructions[0].instruction != NULL && execution_unit_instructions[0].value == 0) {
        SInt32 ringIndex;
        PCodeInstruction *object;
        object = execution_unit_instructions[0].instruction;
        ringIndex = 0;
        while (ringIndex < 16 && instruction_ring[ringIndex].instruction != object)
            ringIndex++;
        instruction_ring[ringIndex].value = 1;
        execution_unit_instructions[0].instruction = NULL;
        data_00582dd8 = object;
    }

    if (execution_unit_instructions[1].instruction != NULL && execution_unit_instructions[1].value == 0) {
        SInt32 ringIndex;
        PCodeInstruction *object;
        object = data_00582d98;
        ringIndex = 0;
        while (ringIndex < 16 && instruction_ring[ringIndex].instruction != object)
            ringIndex++;
        instruction_ring[ringIndex].value = 1;
        execution_unit_instructions[1].instruction = NULL;
        data_00582ddc = object;
    }

    if (execution_unit_instructions[2].instruction != NULL && execution_unit_instructions[2].value == 0) {
        SInt32 ringIndex;
        PCodeInstruction *object;
        object = data_00582da0;
        ringIndex = 0;
        while (ringIndex < 16 && instruction_ring[ringIndex].instruction != object)
            ringIndex++;
        instruction_ring[ringIndex].value = 1;
        execution_unit_instructions[2].instruction = NULL;
    }

    if (execution_unit_instructions[7].instruction != NULL && execution_unit_instructions[7].value == 0) {
        SInt32 ringIndex;
        PCodeInstruction *object;
        object = data_00582dc8;
        ringIndex = 0;
        while (ringIndex < 16 && instruction_ring[ringIndex].instruction != object)
            ringIndex++;
        instruction_ring[ringIndex].value = 1;
        execution_unit_instructions[7].instruction = NULL;
    }

    if (execution_unit_instructions[5].instruction != NULL && execution_unit_instructions[5].value == 0) {
        SInt32 ringIndex;
        PCodeInstruction *object;
        object = data_00582db8;
        ringIndex = 0;
        while (ringIndex < 16 && instruction_ring[ringIndex].instruction != object)
            ringIndex++;
        instruction_ring[ringIndex].value = 1;
        execution_unit_instructions[5].instruction = NULL;
    }

    if (data_00582dd0 != 0 && execution_unit_instructions[8].value == 0) {
        SInt32 ringIndex;
        PCodeInstruction *object;
        object = execution_unit_instructions[8].instruction;
        ringIndex = 0;
        while (ringIndex < 16 && instruction_ring[ringIndex].instruction != object)
            ringIndex++;
        instruction_ring[ringIndex].value = 1;
        data_00582dd0 = 0;
    }

    {
        SInt32 ringIndex;
        FuncArg *object;
        if ((object = data_00582da8) != NULL && execution_unit_instructions[3].value == 0 &&
            (object->sclass == 0xa8 || object->sclass == 0xa9)) {
            PCodeInstruction *slotObject;
            slotObject = execution_unit_instructions[3].instruction;
            ringIndex = 0;
            while (ringIndex < 16 && instruction_ring[ringIndex].instruction != slotObject)
                ringIndex++;
            instruction_ring[ringIndex].value = 1;
            data_00582da8 = NULL;
        }
    }

    if (data_00582db0 != 0 && execution_unit_instructions[4].value == 0 &&
        execution_unit_instructions[5].instruction == NULL) {
        SInt32 count;
        PCodeInstruction *object;
        object = execution_unit_instructions[4].instruction;
        count = opcode_sclass_info[object->opcode].thirdStageCycles;
        execution_unit_instructions[5].instruction = object;
        execution_unit_instructions[5].value = count;
        data_00582db0 = 0;
    }

    if (data_00582da8 != NULL && execution_unit_instructions[3].value == 0 && data_00582db0 == 0) {
        PCodeInstruction *object;
        object = execution_unit_instructions[3].instruction;
        count = opcode_sclass_info[object->opcode].secondStageCycles;
        execution_unit_instructions[4].instruction = object;
        execution_unit_instructions[4].value = count;
        data_00582da8 = NULL;
    }

    if (data_00582dc0 != 0 && execution_unit_instructions[6].value == 0 &&
        execution_unit_instructions[7].instruction == NULL) {
        SInt32 count;
        PCodeInstruction *object;
        object = execution_unit_instructions[6].instruction;
        count = opcode_sclass_info[object->opcode].secondStageCycles;
        execution_unit_instructions[7].instruction = object;
        execution_unit_instructions[7].value = count;
        data_00582dc0 = 0;
    }
}

void assign_instruction_to_execution_unit(struct PCodeInstruction *instruction)
{
    unsigned int index;
    int value;
    unsigned int opcode = instruction->opcode;
    index = machineOpcodeInfo604[opcode].executionUnit;
    value = opcode_sclass_info[opcode].initialStageCycles;
    if ((index == 0) && (execution_unit_instructions[0].instruction != NULL)) {
        index = 1;
    }
    DAT_00582de4 = 1 + DAT_00582de4;
    data_00582de0 = data_00582de0 + -1;
    instruction_ring[next_instruction_slot].instruction = instruction;
    instruction_ring[next_instruction_slot].value = 0;
    next_instruction_slot = next_instruction_slot + 1 & 0xf;
    execution_unit_instructions[index].instruction = instruction;
    execution_unit_instructions[index].value = value;
}

static void ZeroArray(InstructionValueEntry *arr, SInt32 n)
{
    SInt32 i;

    for (i = 0; i < n; i++)
        arr[i].instruction = NULL;
}

static void ZeroInstructions(InstructionValueEntry *arr, SInt32 n)
{
    SInt32 i;
    for (i = 0; i < n; i++)
        arr[i].instruction = NULL;
}

int can_issue_instruction(struct PCodeInstruction *instruction)
{
    unsigned int category;
    PCodeInstruction *candidate;
    PCodeInstruction *ref;
    int firstMissing;
    int secondMissing;
    int noFirst;
    int enabled;
    category = machineOpcodeInfo604[(int)instruction->opcode].executionUnit;
    enabled = data_00582de0;
    if (enabled == 0)
        return 0;
    if (category == 0) {
        firstMissing = noFirst = !execution_unit_instructions[0].instruction;
        secondMissing = 0;
        if ((candidate = execution_unit_instructions[1].instruction) == NULL)
            secondMissing = 1;
        if (noFirst == 0 && secondMissing == 0)
            return 0;
        if (firstMissing != 0 && secondMissing != 0)
            return 1;
        if (firstMissing == 0)
            candidate = execution_unit_instructions[0].instruction;
        if (Scheduler_ReturnZero(instruction, candidate, 0) != 0)
            return 0;
        ref = data_00582dd8;
        if (Scheduler_ReturnZero(instruction, ref, 0) != 0)
            return 0;
        ref = data_00582ddc;
        if (Scheduler_ReturnZero(instruction, ref, 0) != 0)
            return 0;
    } else if (execution_unit_instructions[category].instruction != NULL) {
        return 0;
    }
    return 1;
}

void fn_0052eb60(void)
{
    ZeroInstructions(execution_unit_instructions, 9);
    data_00582de0 = 0x10;
    DAT_00582de4 = 0;
    instruction_retire_index = 0;
    next_instruction_slot = 0;
    ZeroInstructions(instruction_ring, 16);
    data_00582dd8 = NULL;
    data_00582ddc = NULL;
}

SInt32 get_size_rec_latency(PCodeInstruction *p)
{
    SInt32 n = machineOpcodeInfo604[p->opcode].latency;
    if (p->flags & fRecordBit) {
        n += 2;
    }
    if (p->opcode == 0x27 || p->opcode == 0x36) {
        n += p->operand_count - 2;
    }
    return n;
}
