
#include "msl/signal.h"
#include "msl/critical_regions_win32.h"
#include "msl/startup_win32.h"

/* Globals (generated from the original's .bss) */
unsigned int data_0057d2a4[28/sizeof(unsigned int)];
unsigned int exchange_indexed_value(int index, unsigned int value)
{
    unsigned int old;
    if (index < 1 || index > 6) {
        *_GetThreadLocalData() = 36;
        return -1U;
    }
    __begin_critical_region(4U);
    old = data_0057d2a4[index];
    data_0057d2a4[index] = value;
    __end_critical_region(4U);
    return old;
}

int __cdecl raise(int signalNumber)
{
  unsigned int handler;

  if ((signalNumber < 1) || (6 < signalNumber)) {
    return -1;
  }
  __begin_critical_region(4);
  handler = data_0057d2a4[signalNumber];
  if (handler != 1) {
    data_0057d2a4[signalNumber] = 0;
  }
  __end_critical_region(4);
  if ((handler == 1) || ((handler == 0) && (signalNumber == 1))) {
    return 0;
  }
  if (handler == 0) {
    exit(0);
  }
  (*(code *)handler)(signalNumber);
  return 0;
}

