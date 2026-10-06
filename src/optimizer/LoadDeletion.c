#define CERROR_FILE "unknown.c"
#include "compiler/common.h"
#include "compiler/LoadDeletion.h"
#include "compiler/enode.h"
#include "compiler/objects.h"
#include "compiler/scopes.h"
#include "compiler/types.h"
#include "compiler/BE_elf.h"
#include "compiler/BE_symbol.h"
#include "compiler/BitVectors.h"
#include "compiler/CException.h"
#include "compiler/CExpr2.h"
#include "compiler/CFunc.h"
#include "compiler/CInline.h"
#include "compiler/CPrec.h"
#include "compiler/CPrep.h"
#include "compiler/CRTTI.h"
#include "compiler/CTemplateFunc.h"
#include "compiler/CTemplateNew.h"
#include "compiler/CTemplateTools.h"
#include "compiler/CodeMotion.h"
#include "compiler/CompilerTools.h"
#include "compiler/ConstantPropagation.h"
#include "compiler/DWARF.h"
#include "compiler/IROUseDef.h"
#include "compiler/InlineAsmPPC.h"
#include "compiler/InterferenceGraph.h"
#include "compiler/Intrinsics.h"
#include "compiler/IroCSE.h"
#include "compiler/IroLoop.h"
#include "compiler/IroVars.h"
#include "compiler/LoopDetection.h"
#include "compiler/LoopOptimization.h"
#include "compiler/ObjGen_PPC_EABI.h"
#include "compiler/PCode.h"
#include "compiler/PCodeAssembly.h"
#include "compiler/Registers.h"
#include "compiler/StrengthReduction.h"
#include "compiler/Switch.h"
#include "compiler/VectorArraysToRegs.h"

/* Globals (generated from the original's .bss) */
int load_index_count;
VectorArrayEntry * load_index_entries;
struct CodeMotionBits * codeMotionBits;
unsigned char data_00582c9c;
int * block_record_counts;
SInt32 * load_liveness_record_start;
/* Per-entry storage for the two load-deletion bit sets. */
void LoadDeletion_BuildLoadLivenessSets(void)
{
    PCodeBlock *cb;
    CBlockData *bd;
    PCodeInstruction *obj;
    PCodeInstruction *o;
    PCodeOperand *rec;
    E *p;
    UInt32 *setA;
    UInt32 *setB;
    SInt32 num;
    SInt32 i;
    SInt32 start;
    SInt32 n;

    for (cb = gPCodeBlocks; cb != NULL; cb = cb->next) {
        bd = data_00587c98 + cb->index;
        setA = bd->generatedLoads;
        setB = bd->killedLoads;
        CRTTI_FillWords(setA, data_0058820c, 0);
        CRTTI_FillWords(setB, data_0058820c, 0);
        start = load_liveness_record_start[cb->index];
        for (obj = cb->instructions; obj != NULL; obj = obj->next) {
            if ((obj->flags & fIsBranch) == 0 && obj->operand_count != 0) {
                rec = obj->operandData.operands;
                n = obj->operand_count;
                while (n--) {
                    if ((rec->kind == PCOp_GPR || rec->kind == PCOp_VR) && (rec->flags & 2) != 0) {
                        p = immediateLoadLiveness;
                        for (i = 0; data_0058820c > i; i++, p++) {
                            if (((PCodeInstruction *)p->inst)->operandData.operands[0].kind == rec->kind &&
                                (((PCodeInstruction *)p->inst)->operandData.operands[0].value.reg == rec->value.reg ||
                                 ((PCodeInstruction *)p->inst)->operandData.operands[1].value.reg == rec->value.reg)) {
                                if (((PCodeInstruction *)p->inst)->block == cb)
                                    setA[i >> 5] &= ~(1 << (i & 31));
                                else
                                    setB[i >> 5] |= 1 << (i & 31);
                            }
                        }
                    }
                    rec++;
                }
                if (obj->opcode == PC_LI && obj->operandData.operands[0].value.reg >= 0x20) {
                    setA[start >> 5] |= 1 << (start & 31);
                    start++;
                }
                if ((obj->opcode == PC_VSPLTISB || obj->opcode == PC_VSPLTISH || obj->opcode == PC_VSPLTISW) &&
                    obj->operandData.operands[0].value.reg >= 0x20) {
                    setA[start >> 5] |= 1 << (start & 31);
                    start++;
                }
            }
        }
    }
}

/* Instruction records inspected for counting. */
void LoadDeletion_RecordImmediateLoadLiveness(void)
{
    PCodeInstruction *instruction;
    struct CodeMotionEntryLink *entry;
    CodeMotionEntry *definition;
    CodeMotionEntry *use;
    PCodeBlock *block;
    struct E *record;
    int definitionIndex;
    UInt32 *liveBits;
    int registerIndex;
    int useIndex;

    immediateLoadLiveness =
        (struct E *)CompilerTools_AllocatePoolMemory(data_0058820c * sizeof(*immediateLoadLiveness));
    liveBits = (UInt32 *)CompilerTools_AllocatePoolMemory(((data_00587e38 + 31) >> 5) * sizeof(*liveBits));
    block = gPCodeBlocks;
    while (block != NULL) {
        if (block_record_counts[block->index] != 0) {
            CodeMotion_AllocateBits(liveBits, data_00587fe4[block->index].use_sets[3], data_00587e38);
            record = immediateLoadLiveness +
                     (load_liveness_record_start[block->index] + block_record_counts[block->index] - 1);
            instruction = block->reverse_instructions;
            if (instruction != NULL) {
                do {
                    if ((instruction->flags & PCodeInstruction_SkipCodeMotion) == 0 &&
                        instruction->operand_count != 0) {
                        if (instruction->opcode == PC_LI) {
                            registerIndex = instruction->operandData.operands[0].value.reg;
                            if (registerIndex >= 32) {
                                record->inst = instruction;
                                record->flag = 0;
                                entry = code_motion_register_use_heads[registerIndex];
                                if (entry != NULL) {
                                    do {
                                        if ((1 << entry->entry_index & liveBits[entry->entry_index >> 5]) != 0) {
                                            record->flag = 1;
                                            break;
                                        }
                                        entry = entry->next;
                                    } while (entry != NULL);
                                }
                                record--;
                            }
                        }
                        if (instruction->opcode == PC_VSPLTISB || instruction->opcode == PC_VSPLTISH ||
                            instruction->opcode == PC_VSPLTISW) {
                            registerIndex = instruction->operandData.operands[0].value.reg;
                            if (registerIndex >= 32) {
                                record->inst = instruction;
                                record->flag = 0;
                                entry = register_use_entry_heads[registerIndex];
                                if (entry != NULL) {
                                    do {
                                        if ((1 << entry->entry_index & liveBits[entry->entry_index >> 5]) != 0) {
                                            record->flag = 1;
                                            break;
                                        }
                                        entry = entry->next;
                                    } while (entry != NULL);
                                }
                                record--;
                            }
                        }
                        definition = &code_motion_entries[definitionIndex = instruction->useStart];
                        for (; definitionIndex < codeMotionEntryCount && definition->instruction == instruction;
                             definitionIndex++) {
                            if (definition->kind == 0) {
                                entry = code_motion_register_use_heads[definition->value.reg];
                                if (entry != NULL) {
                                    do {
                                        liveBits[entry->entry_index >> 5] &= ~(1 << (entry->entry_index & 31));
                                        entry = entry->next;
                                    } while (entry != NULL);
                                }
                            } else if (definition->kind == 1) {
                                entry = codeMotionUseEntryHeads[definition->value.reg];
                                if (entry != NULL) {
                                    do {
                                        liveBits[entry->entry_index >> 5] &= ~(1 << (entry->entry_index & 31));
                                        entry = entry->next;
                                    } while (entry != NULL);
                                }
                            } else if (definition->kind == 9) {
                                entry = register_use_entry_heads[definition->value.reg];
                                if (entry != NULL) {
                                    do {
                                        liveBits[entry->entry_index >> 5] &= ~(1 << (entry->entry_index & 31));
                                        entry = entry->next;
                                    } while (entry != NULL);
                                }
                            }
                            definition++;
                        }
                        use = &cm_entries[useIndex = instruction->definitionStart];
                        for (; useIndex < data_00587e38 && use->instruction == instruction; useIndex++) {
                            if (use->kind == 0 || use->kind == 1 || use->kind == 9) {
                                liveBits[useIndex >> 5] |= 1 << useIndex;
                            }
                            use++;
                        }
                    }
                    instruction = instruction->previous;
                } while (instruction != NULL);
            }
        }
        block = block->next;
    }
}

void LoadDeletion_InitializeLoadLivenessRecordCounts(void)
{
    PCodeBlock *block;
    PCodeInstruction *instruction;
    unsigned int count;

    block_record_counts = CompilerTools_AllocatePoolMemory(gPCodeBlockCount * sizeof(*block_record_counts));
    load_liveness_record_start =
        CompilerTools_AllocatePoolMemory(gPCodeBlockCount * sizeof(*load_liveness_record_start));
    data_0058820c = 0;
    for (block = gPCodeBlocks; block != NULL; block = block->next) {
        load_liveness_record_start[block->index] = data_0058820c;
        count = 0;
        for (instruction = block->instructions; instruction != NULL; instruction = instruction->next) {
            if (instruction->opcode == PC_LI || (unsigned short)(instruction->opcode - 350) <= 2) {
                if (instruction->operandData.operands[0].value.reg >= 32) {
                    ++data_0058820c;
                    ++count;
                }
            }
        }
        block_record_counts[block->index] = count;
    }
}

int fn_0052ce10(void)
{
    struct AggregateRecord *analysis;
    CodeMotionBits *bitsets;
    int index;

    data_00582c9c = 0;
    analysis = VectorArraysToRegs_BuildAggregateRecords();
    if (analysis != NULL) {
        fn_0052d8d0(analysis);
        if (load_index_count > 0) {
            COpt_SetLoopCodeMotionMode(0);
            VectorArraysToRegs_BuildLoadIndexEntries(analysis);
            codeMotionBits = CompilerTools_AllocatePoolMemory(gPCodeBlockCount * sizeof(CodeMotionBits));
            bitsets = codeMotionBits;
            for (index = 0; index < gPCodeBlockCount; ++index) {
                bitsets->gen = CompilerTools_AllocatePoolMemory(((load_index_count + 31) >> 5) * sizeof(*bitsets->gen));
                bitsets->kill =
                    CompilerTools_AllocatePoolMemory(((load_index_count + 31) >> 5) * sizeof(*bitsets->kill));
                bitsets->in = CompilerTools_AllocatePoolMemory(((load_index_count + 31) >> 5) * sizeof(*bitsets->in));
                bitsets->out = CompilerTools_AllocatePoolMemory(((load_index_count + 31) >> 5) * sizeof(*bitsets->out));
                bitsets++;
            }
            VectorArraysToRegs_ComputeGenKill(analysis);
            SpillCode_BuildBlockOrder();
            VectorArraysToRegs_ComputeInOutBits();
            fn_0052cf10(analysis);
        }
    }
    CompilerTools_ResetPool();
    return data_00582c9c;
}

/* Class and allocation-entry list used by the allocation pass. */
static struct AggregateRecord *FindCandidate(struct AggregateRecord *list, Object *object)
{
    struct AggregateRecord *match;
    for (match = list; match; match = match->next) {
        if (match->object == object)
            return match;
    }
    return NULL;
}

static void CheckUses(long classIndex, VectorArrayUse *entries, PCodeInstruction *classType,
                      struct AggregateRecord *list)
{
    VectorArrayUse *entry;
    struct AggregateRecord *match;
    entry = entries;
    if (entries != NULL) {
        do {
            if (entry != NULL && fn_0052d1e0(classIndex, entry->instructionIndex) == 0) {
                match = FindCandidate(list, classType->operandData.operands[2].object);
                match->flag = 1;
                break;
            }
            entry = entry->next;
        } while (entry != NULL);
    }
}

void fn_0052cf10(struct AggregateRecord *candidates)
{
    long classIndex;
    int candidateCount;
    int slotCount;
    struct AggregateRecord **head;
    struct AggregateRecord *candidate;
    int slot;
    struct AggregateRecord *previous;
    struct AggregateRecord *smallest;
    long smallestTotal;
    struct AggregateRecord *scan;
    struct AggregateRecord *remaining;
    long index;
    struct AggregateRecord *next;

    for (classIndex = 0; classIndex < load_index_count; classIndex++) {
        CheckUses(classIndex, load_index_entries[classIndex].uses, load_index_entries[classIndex].array, candidates);
    }
    candidateCount = 0;
    slotCount = 0;
    head = &candidates;
    candidate = candidates;
    while (candidate != NULL) {
        if (candidate->flag != 0) {
            *head = candidate->next;
            candidate = *head;
        } else {
            candidateCount++;
            slotCount += candidate->count;
            for (slot = 0; slot < candidate->count; slot++) {
                candidate->index += candidate->slots[slot];
            }
            candidate = candidate->next;
        }
    }
    if (candidates != NULL) {
        while (slotCount > 32) {
            smallestTotal = 0;
            smallest = NULL;
            scan = candidates;
            while (scan != NULL) {
                if (smallest != NULL) {
                    if (scan->index < smallestTotal) {
                        smallestTotal = scan->index;
                        smallest = scan;
                    }
                } else {
                    smallest = scan;
                    smallestTotal = scan->index;
                }
                scan = scan->next;
            }
            if (smallest == NULL) {
                break;
            }
            if (smallest == candidates) {
                candidates = smallest->next;
            } else if ((previous = candidates) != NULL) {
                do {
                    if ((next = previous->next) == smallest) {
                        previous->next = smallest->next;
                        break;
                    }
                    previous = next;
                } while (next != NULL);
            }
            candidateCount--;
            slotCount -= smallest->count;
        }
        remaining = candidates;
        if (remaining == NULL) {
            return;
        }
        while (remaining != NULL) {
            for (slot = 0; slot < remaining->count; slot++) {
                remaining->slots[slot] = gUsedVirtualRegistersVR;
                gUsedVirtualRegistersVR++;
            }
            remaining = remaining->next;
        }
        if (candidates != NULL) {
            for (index = 0; index < load_index_count; index++) {
                VectorArraysToRegs_ReplaceArrayUsesWithVMR(candidates, index);
            }
        }
    }
}

/* Pointer at the beginning of a ten-byte table entry. */
