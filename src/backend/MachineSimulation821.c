#define CERROR_FILE "SpillCode.c"
#include "compiler/common.h"
#include "compiler/MachineSimulation821.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/types.h"
#include "compiler/CException.h"
#include "compiler/CFunc.h"
#include "compiler/DWARF.h"
#include "compiler/IROUseDef.h"
#include "compiler/InlineAsmPPC.h"
#include "compiler/InterferenceGraph.h"
#include "compiler/IroCSE.h"
#include "compiler/IroLoop.h"
#include "compiler/IroVars.h"
#include "compiler/LiveVariables.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"

/* Declarations gathered from the merged files. */

#include <string.h>

/* Globals (generated from the original's .bss) */
SInt32 data_00583018[8/sizeof(SInt32)];
unsigned char data_00583020[8/sizeof(unsigned char)];
SInt32 data_00583028;
unsigned char data_00583030[8/sizeof(unsigned char)];
struct PCodeInstruction * data_00583038[8/sizeof(struct PCodeInstruction *)];
SInt32 data_00583040;
int data_00583048;
UInt32 data_0058304c;
UInt32 data_00583050;
unsigned int record_enqueue_index;
QueueSlot queue_slots[6];
SInt32 data_00583060;
SInt32 data_00583068;
SInt32 data_00583070;
SInt32 data_00583078;
SInt32 data_00583080;

/* 0x5842e1, byte access */

/* PCodeBlock: the object a liveness entry is indexed by; its block number
 * lives at 0x1c. */

/* Per-block liveness record: four bit vectors. */

/* TYPESTRUCT record with the byte classification field at 0x0e. */
int get_instruction_opcode_table_entry(PCodeInstruction *instruction)
{
    return DAT_00578e55[instruction->opcode * 6];
}

void fn_00530660(void)
{
    SInt32 i;
    i = 0;
    do {
        if (data_00583018[i * 2] != 0 && data_00583018[i * 2 + 1] != 0)
            data_00583018[i * 2 + 1]--;
        i++;
    } while (i < 6);
    if (data_0058304c > 0 && queue_slots[data_00583050].flag != 0) {
        queue_slots[data_00583050].obj = NULL;
        data_0058304c--;
        data_00583048++;
        data_00583050 = (data_00583050 + 1) % 6;
        if (data_0058304c > 0 && queue_slots[data_00583050].flag != 0) {
            queue_slots[data_00583050].obj = NULL;
            data_0058304c--;
            data_00583048++;
            data_00583050 = (1 + data_00583050) % 6;
        }
    }
    if (data_00583018[2] != 0 && data_00583018[3] == 0) {
        SInt32 i;
        struct PCodeInstruction *key = (struct PCodeInstruction *)data_00583018[2];
        for (i = 0; i < 6 && queue_slots[i].obj != key; i++)
            ;
        queue_slots[i].flag = 1;
        data_00583018[2] = 0;
    }
    if (data_00583018[8] != 0 && data_00583018[9] == 0) {
        SInt32 i;
        struct PCodeInstruction *key = (struct PCodeInstruction *)data_00583018[8];
        for (i = 0; i < 6 && queue_slots[i].obj != key; i++)
            ;
        queue_slots[i].flag = 1;
        data_00583018[8] = 0;
    }
    if (data_00583018[0] != 0 && data_00583018[1] == 0) {
        SInt32 i;
        struct PCodeInstruction *key = (struct PCodeInstruction *)data_00583018[0];
        for (i = 0; i < 6 && queue_slots[i].obj != key; i++)
            ;
        queue_slots[i].flag = 1;
        data_00583018[0] = 0;
    }
    if (data_00583018[6] != 0 && data_00583018[7] == 0 && data_00583018[8] == 0) {
        SInt32 count;
        PCodeInstruction *object = (PCodeInstruction *)data_00583018[6];
        count = data_00578e53[object->opcode * 6];
        data_00583018[8] = (SInt32)object;
        data_00583018[9] = count;
        data_00583018[6] = 0;
    }
}

static inline long RecordValue(IndexedRecord *record)
{
    return (int)record;
}

static inline void EnqueueRecord(IndexedRecord *record)
{
    data_00583018[record_enqueue_index * 2 + 16] = RecordValue(record);
    data_00583018[record_enqueue_index * 2 + 17] = 0;
    record_enqueue_index = (record_enqueue_index + 1) % 6;
}

void fn_00530830(IndexedRecord *record)
{
    int slot;
    int tableOffset;

    tableOffset = record->index * 6;
    slot = DAT_00578e50[tableOffset];

    data_0058304c = data_0058304c + 1;
    data_00583048 = data_00583048 - 1;
    EnqueueRecord(record);
    data_00583018[slot * 2] = RecordValue(record);
    data_00583018[slot * 2 + 1] = DAT_00578e52[tableOffset];
}

int fn_005308b0(struct PCodeInstruction *pcode)
{
    struct PCodeInstruction *other;
    if (data_00583048 == 0)
        return 0;
    if (data_00583018[DAT_00578e50[pcode->opcode * 6] * 2] != 0)
        return 0;
    if ((pcode->flags & fIsWrite) != 0) {
        other = data_00583038[0];
        if (other != NULL && (other->flags & fIsWrite) != 0)
            return 0;
    }
    return 1;
}

static inline void SetSpillWord(void *storage, unsigned int value)
{
    unsigned int *word = storage;
    *word = value;
}

void reset_spill_state(void)
{
    SetSpillWord(data_00583018, 0);
    SetSpillWord(data_00583020, 0);
    data_00583028 = 0;
    SetSpillWord(data_00583030, 0);
    SetSpillWord(data_00583038, 0);
    data_00583040 = 0;
    data_00583048 = 6;
    data_0058304c = 0;
    data_00583050 = 0;
    record_enqueue_index = 0;
    SetSpillWord(queue_slots, 0);
    data_00583060 = 0;
    data_00583068 = 0;
    data_00583070 = 0;
    data_00583078 = 0;
    data_00583080 = 0;
}

int get_instruction_cost(PCodeInstruction *instruction)
{
    int cost = instruction_costs[instruction->opcode * 6];

    if (instruction->flags & fRecordBit) {
        cost += 2;
    }
    if (instruction->opcode == PC_LMW || instruction->opcode == PC_STMW) {
        cost += instruction->operand_count - 2;
    }
    return cost;
}
