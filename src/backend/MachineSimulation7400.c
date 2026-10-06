#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "compiler/MachineSimulation7400.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/types.h"
#include "compiler/DWARF.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"
#include "compiler/Scheduler.h"
#include <string.h>

/* Globals (generated from the original's .bss) */
CountedSlot pipeline_slots[18];
struct PCodeInstruction * DAT_00582f08;
int DAT_00582f0c;
struct PCodeInstruction * DAT_00582f10;
int DAT_00582f14;
struct PCodeInstruction * DAT_00582f18;
int DAT_00582f1c;
struct PCodeInstruction * DAT_00582f20;
int DAT_00582f24;
struct PCodeInstruction * DAT_00582f28;
int DAT_00582f2c;
struct PCodeInstruction * DAT_00582f30;
int DAT_00582f34;
struct PCodeInstruction * DAT_00582f38;
int DAT_00582f3c;
struct PCodeInstruction * DAT_00582f40;
int DAT_00582f44;
PCodeInstruction * DAT_00582f48;
int DAT_00582f4c;
PCodeInstruction * primary_instruction;
int DAT_00582f54;
struct PCodeInstruction * DAT_00582f58;
int DAT_00582f5c;
struct PCodeInstruction * DAT_00582f60;
int DAT_00582f64;
PCodeInstruction * completed_instruction;
int DAT_00582f6c;
PCodeInstruction * DAT_00582f70;
int DAT_00582f74;
PCodeInstruction * DAT_00582f78;
int DAT_00582f7c;
PCodeInstruction * DAT_00582f80;
int DAT_00582f84;
struct PCodeInstruction * DAT_00582f88;
int DAT_00582f8c;
PCodeInstruction * pipelineCompletedInstruction;
PCodeInstruction * pipeline_completed_instruction;
int DAT_00582f98;
int queued_instruction_count;
unsigned int pipeline_index;
SInt32 simulationWriteIndex;
CountedSlot instruction_queue[8];
unsigned int _DAT_00582fb0;
unsigned int _DAT_00582fb8;
unsigned int _DAT_00582fc0;
unsigned int _DAT_00582fc8;
unsigned int _DAT_00582fd0;
unsigned int _DAT_00582fd8;
unsigned int _DAT_00582fe0;
int fn_0052f370(PCodeInstruction *instruction)
{
    return DAT_00577660[instruction->opcode].kind == '\n';
}

int lookup_instruction_opcode_entry(PCodeInstruction *instruction)
{
    return DAT_00577660[instruction->opcode].opcodeEntryValue;
}

static void Advance(PCodeInstruction *o, PCodeInstruction **next, const unsigned char *tab)
{
    int v;
    PCodeInstruction *saved = o;
    v = (int)(char)tab[o->opcode * 7];
    next[0] = saved;
    next[1] = (PCodeInstruction *)v;
}

void advance_pipeline(void)
{
    int stageIndex;

    pipelineCompletedInstruction = NULL;
    pipeline_completed_instruction = NULL;
    for (stageIndex = 0; stageIndex < 18; stageIndex++) {
        if ((pipeline_slots[stageIndex].instruction != NULL) && (pipeline_slots[stageIndex].status != 0)) {
            --pipeline_slots[stageIndex].status;
        }
    }
    if ((queued_instruction_count != 0) && (instruction_queue[pipeline_index].status != 0)) {
        instruction_queue[pipeline_index].instruction = NULL;
        --queued_instruction_count;
        ++DAT_00582f98;
        pipeline_index = (pipeline_index + 1) & 7;
        if ((queued_instruction_count != 0) && (instruction_queue[pipeline_index].status != 0)) {
            instruction_queue[pipeline_index].instruction = NULL;
            --queued_instruction_count;
            ++DAT_00582f98;
            pipeline_index = (pipeline_index + 1) & 7;
        }
    }
    if ((DAT_00582f08 != NULL) && (DAT_00582f0c == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = DAT_00582f08;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        DAT_00582f08 = NULL;
        pipelineCompletedInstruction = completedInstruction;
    }
    if ((primary_instruction != NULL) && (DAT_00582f54 == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = primary_instruction;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        primary_instruction = NULL;
    }
    if ((DAT_00582f20 != NULL) && (DAT_00582f24 == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = DAT_00582f20;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        DAT_00582f20 = NULL;
    }
    if ((DAT_00582f38 != NULL) && (DAT_00582f3c == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = DAT_00582f38;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        DAT_00582f38 = NULL;
    }
    if ((DAT_00582f40 != NULL) && (DAT_00582f44 == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = DAT_00582f40;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        DAT_00582f40 = NULL;
    }
    if ((pipeline_slots[0].instruction != NULL) && (pipeline_slots[0].status == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = pipeline_slots[0].instruction;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        pipeline_slots[0].instruction = NULL;
    }
    if ((DAT_00582f48 != NULL) && (DAT_00582f4c == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = DAT_00582f48;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        DAT_00582f48 = NULL;
    }
    if ((completed_instruction != NULL) && (DAT_00582f6c == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = completed_instruction;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        completed_instruction = NULL;
    }
    if ((DAT_00582f88 != NULL) && (DAT_00582f8c == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = DAT_00582f88;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        DAT_00582f88 = NULL;
    }
    if ((DAT_00582f10 != NULL) && (DAT_00582f14 == 0)) {
        int slotIndex;
        PCodeInstruction *completedInstruction;
        completedInstruction = DAT_00582f10;
        for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
             slotIndex++) {
        }
        instruction_queue[slotIndex].status = 1;
        DAT_00582f10 = NULL;
        pipeline_completed_instruction = completedInstruction;
    }
    {
        PCodeInstruction *instruction = DAT_00582f28;
        if ((instruction != NULL) && (DAT_00582f2c == 0) &&
            ((instruction->opcode == PC_FDIV) || (instruction->opcode == PC_FDIVS))) {
            int slotIndex;
            PCodeInstruction *completedInstruction;
            completedInstruction = DAT_00582f28;
            for (slotIndex = 0; (slotIndex < 8) && (instruction_queue[slotIndex].instruction != completedInstruction);
                 slotIndex++) {
            }
            instruction_queue[slotIndex].status = 1;
            DAT_00582f28 = NULL;
        }
    }
    if (((DAT_00582f30 != NULL) && (DAT_00582f34 == 0)) && (DAT_00582f38 == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f30, &DAT_00582f38, &DAT_00577660[0].stage3Latency);
        DAT_00582f30 = NULL;
    }
    if (((DAT_00582f28 != NULL) && (DAT_00582f2c == 0)) && (DAT_00582f30 == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f28, &DAT_00582f30, &DAT_00577660[0].stage2Latency);
        DAT_00582f28 = NULL;
    }
    if (((DAT_00582f18 != NULL) && (DAT_00582f1c == 0)) && (DAT_00582f20 == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f18, &DAT_00582f20, &DAT_00577660[0].stage2Latency);
        DAT_00582f18 = NULL;
    }
    if (((DAT_00582f60 != NULL) && (DAT_00582f64 == 0)) && (completed_instruction == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f60, &completed_instruction, &DAT_00577660[0].stage3Latency);
        DAT_00582f60 = NULL;
    }
    if (((DAT_00582f58 != NULL) && (DAT_00582f5c == 0)) && (DAT_00582f60 == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f58, &DAT_00582f60, &DAT_00577660[0].stage2Latency);
        DAT_00582f58 = NULL;
    }
    if (((DAT_00582f80 != NULL) && (DAT_00582f84 == 0)) && (DAT_00582f88 == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f80, &DAT_00582f88, &DAT_00577660[0].stage4Latency);
        DAT_00582f80 = NULL;
    }
    if (((DAT_00582f78 != NULL) && (DAT_00582f7c == 0)) && (DAT_00582f80 == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f78, &DAT_00582f80, &DAT_00577660[0].stage3Latency);
        DAT_00582f78 = NULL;
    }
    if (((DAT_00582f70 != NULL) && (DAT_00582f74 == 0)) && (DAT_00582f78 == NULL)) {
        PCodeInstruction *instruction;
        Advance(instruction = DAT_00582f70, &DAT_00582f78, &DAT_00577660[0].stage2Latency);
        DAT_00582f70 = NULL;
    }
}

void queue_instruction(PCodeInstruction *obj)
{ /* signature unknown: cdecl, arguments at [esp+4], [esp+8], ... */
    SInt32 t;
    SInt32 c;

    t = DAT_00577660[obj->opcode].kind;
    c = DAT_00577660[obj->opcode].cost;

    queued_instruction_count++;
    DAT_00582f98--;
    instruction_queue[simulationWriteIndex].instruction = obj;
    instruction_queue[simulationWriteIndex].status = 0;
    simulationWriteIndex = (simulationWriteIndex + 1) & 7;
    if (t == 2 && DAT_00582f08 == NULL) {
        t = 1;
    }
    pipeline_slots[t].instruction = obj;
    pipeline_slots[t].status = c;
}

int can_issue_instruction_in_pipeline_slots(PCodeInstruction *node)
{
    int primaryMissing;
    PCodeInstruction *fourth;
    PCodeInstruction *first;
    unsigned firstAbsent;
    int alternateMissing;
    PCodeInstruction *second;
    int secondMissing, thirdMissing;
    PCodeInstruction *primary;
    PCodeInstruction *third;
    PCodeInstruction *other;
    int fourthMissing;
    int kind, firstMissing;

    if (DAT_00582f98 == 0)
        return 0;
    kind = DAT_00577660[node->opcode].kind;
    if (kind == 2) {
        PCodeInstruction *alternate;
        firstAbsent = firstMissing = !(first = DAT_00582f08);
        alternateMissing = !(alternate = DAT_00582f10);
        if (!firstMissing) {
            if (!alternateMissing)
                return 0;
        }
        if (firstAbsent && alternateMissing)
            return 1;
        if (firstAbsent)
            first = alternate;
        if (Scheduler_ReturnZero(node, first, 0) != 0)
            return 0;
        if (Scheduler_ReturnZero(node, pipelineCompletedInstruction, 0) != 0)
            return 0;
        if (Scheduler_ReturnZero(node, pipeline_completed_instruction, 0) != 0)
            return 0;
    } else if (kind == 14 || kind == 9 || kind == 10 || kind == 11) {
        primaryMissing = !(primary = primary_instruction);
        secondMissing = !(second = DAT_00582f70);
        thirdMissing = !(third = DAT_00582f58);
        fourthMissing = !(fourth = DAT_00582f48);
        if (kind == 10) {
            if (!primaryMissing)
                return 0;
            if (secondMissing) {
                if (!thirdMissing)
                    second = third;
                else if (!fourthMissing)
                    second = fourth;
                else
                    second = NULL;
            }
            if (Scheduler_ReturnZero(node, second, 9) != 0)
                return 0;
        } else {
            if (!secondMissing || !thirdMissing || !fourthMissing)
                return 0;
            if (!primaryMissing && Scheduler_ReturnZero(node, primary, 9) != 0)
                return 0;
        }
    } else if (pipeline_slots[kind].instruction != NULL)
        return 0;
    if ((node->flags & fIsWrite) != 0) {
        other = DAT_00582f20;
        if (other != NULL && (other->flags & fIsWrite) != 0)
            return 0;
    }
    return 1;
}

void reset_pipeline_state(void)
{
    int slot;

    for (slot = 0; slot < 18; ++slot) {
        pipeline_slots[slot].instruction = NULL;
    }
    DAT_00582f98 = 8;
    queued_instruction_count = 0;
    pipeline_index = 0;
    simulationWriteIndex = 0;
    instruction_queue[0].instruction = NULL;
    _DAT_00582fb0 = 0;
    _DAT_00582fb8 = 0;
    _DAT_00582fc0 = 0;
    _DAT_00582fc8 = 0;
    _DAT_00582fd0 = 0;
    _DAT_00582fd8 = 0;
    _DAT_00582fe0 = 0;
    pipelineCompletedInstruction = NULL;
    pipeline_completed_instruction = NULL;
}

int get_adjusted_opcode_table_value(PCodeInstruction *record)
{
    int result;

    result = (SInt8)DAT_00577660[record->opcode].baseLatency;
    if ((record->flags & fRecordBit) != 0) {
        result = result + 2;
    }
    if ((record->opcode == PC_LMW) || (record->opcode == PC_STMW)) {
        result = result + (record->operand_count - 2);
    }
    return result;
}
