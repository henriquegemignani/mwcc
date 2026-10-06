#include "runtime/ExceptionTables.h"
#include "msl/alloc_g.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <msl_internal.h>

/* Strings (generated from the original's .data) */
char data_00536030[] = "Unhandled exception: %08x\nAt address:          %08x\n";

/* Globals (generated from the original's .bss) */
struct _NODE * data_0057d000;
int data_0057d004;
char data_0057d008;
#define CERROR_FILE "unknown.c"

unsigned int _MWCHandler(ExceptionInfo *record, int frame, X86ThreadContext *context)
{
  HANDLE file;
  char message[1024];
  DWORD bytesWritten;

  if ((record->flags & 0x66U) != 0) {
    return 1;
  }
  if (record->code == 0xe06d7363U) {
    invoke_function_pointer();
  }
  sprintf(message, data_00536030, record->code, context->eip);
  file = GetStdHandle(0xfffffff4);
  WriteFile(file, message, strlen(message), &bytesWritten, 0);
  return 1;
}

void __cdecl _RegisterExceptionTables(NODE *node)
{
    NODE *previous;
    NODE *current;

    previous = 0;
    for (current = data_0057d000;
         current != 0 && (unsigned int)current->begin->address > (unsigned int)node->begin->address;
         current = current->next) {
        previous = current;
    }
    node->next = current;
    if (previous != 0) {
        previous->next = node;
    } else {
        data_0057d000 = node;
    }
}

void lookup_runtime_record_and_call_value(char *address, RuntimeLookupResult *result)
{
    RuntimeRangeEntry *entries;
    NODE *block;
    RuntimeCallEntry *call;
    int low;
    int middle;
    int call_index;
    int high;
    char *range_address;
    char *instruction;
    char opcode;
    long mode;
    int reg;
    RuntimeRecord *record;
    int modrm;
    int call_count;
    if (data_0057d008 == 0) {
        data_0057d004 = 0;
        data_0057d008 = 1;
    }
    result->record = 0;
    result->value = 0;
    block = data_0057d000;
    while (block != 0 && (unsigned int)block->begin->address > (unsigned int)address) {
        block = block->next;
    }
    if (block == 0) {
        return;
    }
    entries = block->begin;
    low = 0;
    high = ((int)block->end - (int)block->begin) / 8 - 1;
    while (low <= high) {
        middle = (high + low) / 2;
        range_address = entries[(high + low) / 2].address;
        if ((unsigned int)address >= (unsigned int)entries[(high + low) / 2].address && (unsigned int)address < (unsigned int)entries[middle + 1].address) {
            record = entries[middle].record;
            result->record = record;
            if (((int)result->record->flags & 1) == 0) {
                call = record->calls;
                call_index = 0;
                call_count = result->record->call_count;
                while (call_index < call_count) {
                    instruction = call->instruction;
                    if ((char)(opcode = *instruction) == -24) {
                        instruction = instruction + 5;
                    } else if (opcode == -1) {
                        modrm = (unsigned char)instruction[1];
                        instruction = instruction + 2;
                        mode = (int)modrm >> 6;
                        reg = modrm & 7;
                        if (mode != 3) {
                            if (reg == 4) {
                                instruction = instruction + 1;
                            }
                            if (mode == 0 && reg == 5) {
                                instruction = instruction + 4;
                            } else {
                                switch (mode) {
                                case 1:
                                    instruction = instruction + 1;
                                    break;
                                case 2:
                                    instruction = instruction + 4;
                                    break;
                                }
                            }
                        }
                    } else {
                        invoke_function_pointer();
                    }
                    if (instruction == address) {
                        result->value = *(unsigned int *)((int)call + 4);
                        return;
                    }
                    call_index = call_index + 1;
                    call = call + 1;
                }
            }
            result->value = 0;
            return;
        }
        if ((unsigned int)range_address < (unsigned int)address) {
            low = middle + 1;
        } else {
            high = middle - 1;
        }
    }
    return;
}

#pragma auto_inline off

#pragma auto_inline reset

