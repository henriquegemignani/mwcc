
#include "msl/extras.h"
#include "msl/startup_win32.h"
#include <ctype.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <msl_internal.h>

/* Globals (generated from the original's .bss) */
int data_00587c70;
#define CERROR_FILE "unknown.c"

int __cdecl _strnicmp(char *left, char *right, int count)
{
  int i;
  char leftChar;
  char rightChar;

  for (i = 0; i < count; i = i + 1) {
    leftChar = (char)tolower((int)*left++);
    rightChar = (char)tolower((int)*right++);
    if (leftChar < rightChar) {
      return -1;
    }
    if (leftChar > rightChar) {
      return 1;
    }
    if (leftChar == '\0') {
      return 0;
    }
  }
  return 0;
}

int GetHandle(void)
{
  int index;
  int attempts = 0;

  do {
    if (data_00587c70 == 256) {
      data_00587c70 = 3;
    }
    if (_HandleTable[data_00587c70] == 0) {
      index = data_00587c70;
      data_00587c70++;
      return index;
    }
    attempts++;
    data_00587c70++;
  } while (attempts < 256);
  return -1;
}

