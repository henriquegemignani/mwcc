#include "msl/startup_win32.h"
#include "msl/critical_regions_win32.h"
#include "msl/extras.h"
#include <string.h>
#include <stdlib.h>

/* Globals (generated from the original's .bss) */
int data_0057d010[4/sizeof(int)];
struct EnvironmentBlock data_0057d014;
struct CFileRec * data_0058476c;
struct CFileRec * data_00584770;
struct EnvironmentBlock * data_00587170;
char ** _Environ;

#define CERROR_FILE "unknown.c"

#pragma auto_inline off
int *fn_00401de0(void)
{
    return data_0057d010;
}
#pragma auto_inline reset

/* Runtime standard-stream descriptor; the trailing bytes are unnamed state. */

int _CRTStartup(void)
{
    int stringCount;
    int *initCount;
    char *end;
    long blockSize;
    char *strings;
    char *block;
    char *entry;
    char *indexedEntry;
    int index;
    int previousCount;
    CFileRec *stream1;
    CFileRec *stream2;
    CFileRec *stream3;
    char *savedStrings;
    stringCount = 0;
    initCount = fn_00401de0();
    previousCount = *initCount;
    *initCount += 1;
    if (previousCount != 0) {
        return (int)initCount;
    }
    __init_critical_regions();
    stream1 = (CFileRec *)malloc(8);
    _HandleTable[0] = stream1;
    if (stream1 != 0) {
        _HandleTable[0]->handle = (HANDLE)GetStdHandle(-10);
        _HandleTable[0]->readonly = 0;
        _HandleTable[0]->textmode = 0;
    }
    stream2 = (CFileRec *)malloc(8);
    data_0058476c = stream2;
    if (stream2 != 0) {
        data_0058476c->handle = (HANDLE)GetStdHandle(-11);
        data_0058476c->readonly = 0;
        data_0058476c->textmode = 0;
    }
    stream3 = (CFileRec *)malloc(8);
    data_00584770 = stream3;
    if (stream3 != 0) {
        data_00584770->handle = (HANDLE)GetStdHandle(-12);
        data_00584770->readonly = 0;
        data_00584770->textmode = 0;
    }
    data_00587c70 = 3;
    savedStrings = (*(char *(*)())GetEnvironmentStrings)();
    strings = (*(char *(*)())GetEnvironmentStrings)();
    while (*strings == '=') {
        strings = strings + (strlen(strings) + 1);
    }
    end = strings;
    while (*end != 0) {
        end = end + (strlen(end) + 1);
    }
    block = (char *)malloc(blockSize = end - strings);
    data_0057d014.strings = block;
    if (block != 0) {
        memcpy(block, strings, blockSize);
    }
    data_00587170 = &data_0057d014;
    entry = data_00587170->strings;
    while (*entry != 0) {
        stringCount = stringCount + 1;
        entry = entry + (strlen(entry) + 1);
    }
    _Environ = (char **)malloc((stringCount + 1) << 2);
    indexedEntry = data_00587170->strings;
    index = 0;
    while (*indexedEntry != 0) {
        _Environ[index] = indexedEntry;
        index = index + 1;
        indexedEntry = indexedEntry + (strlen(indexedEntry) + 1);
    }
    _Environ[index] = 0;
    return FreeEnvironmentStringsA(savedStrings);
}

int allocate_tls_index(void)
{
  if (DAT_00536228 != 0xffffffffU) {
    return 1;
  }
  DAT_00536228 = TlsAlloc();
  if (DAT_00536228 == 0xffffffffU) {
    return 0;
  }
  if (register_callback(free_tls_index) != 0) {
    return 0;
  }
  return 1;
}

void free_tls_index(void)

{
  if (DAT_00536228 == 0xffffffffU) {
    return;
  }
  TlsFree(DAT_00536228);
  DAT_00536228 = 0xffffffffU;
  return;
}

#pragma auto_inline off
BOOL __cdecl initialize_thread_local_data(unsigned int argument)
{
  ThreadLocalData *threadData;
  BOOL result;

  threadData = (ThreadLocalData *)malloc(0x254);
  if (threadData == 0) {
    return 0;
  }
  threadData->initialValue = 0;
  threadData->secondaryValue = 1;
  threadData->sharedData = DAT_0053622c;
  threadData->secondarySharedData = DAT_0053622c;
  threadData->argument = argument;
  result = TlsSetValue(DAT_00536228, (unsigned int *)threadData);
  return result;
}
#pragma auto_inline reset

int _InitializeMainThreadData(void)
{
  int (*initialize)(void) = allocate_tls_index;
  if (initialize() != 0) {
    if (initialize_thread_local_data(0) != 0) {
      return 1;
    }
  }
  return 0;
}

SInt32 *_GetThreadLocalData(void)
{
SInt32 *pvVar2;
DWORD DStack_c;

  pvVar2 = TlsGetValue(DAT_00536228);
  if (pvVar2 == 0) {
    initialize_thread_local_data(0);
    pvVar2 = TlsGetValue(DAT_00536228);
  }
  if (pvVar2 == 0) {
    HANDLE h = GetStdHandle(0xFFFFFFF4);
    WriteFile(h, PTR_s_Could_not_get_thread_local_data_00536250,
                  strlen(PTR_s_Could_not_get_thread_local_data_00536250),
                  &DStack_c, 0);
    exit(7);
  }
  return pvVar2;
}

