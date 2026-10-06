
#include "msl/critical_regions_win32.h"

/* Globals (generated from the original's .bss) */
struct _RTL_CRITICAL_SECTION DAT_0057d228[5];
void initialize_critical_sections(void)

{int iVar1;
LPCRITICAL_SECTION lpCriticalSection;

  lpCriticalSection = DAT_0057d228;
  iVar1 = 0;
  while (iVar1 < 5) {
    InitializeCriticalSection(lpCriticalSection);
    iVar1 = iVar1 + 1;
    lpCriticalSection = lpCriticalSection + 1;
  }
  return;
}

void delete_critical_sections(void)

{
  int iVar1;
  LPCRITICAL_SECTION lpCriticalSection;

  lpCriticalSection = DAT_0057d228;
  for (iVar1 = 0; iVar1 < 5; iVar1 = iVar1 + 1) {
    DeleteCriticalSection(lpCriticalSection);
    lpCriticalSection = lpCriticalSection + 1;
  }
  return;
}

void __begin_critical_region(unsigned int a)
{
  EnterCriticalSection(&DAT_0057d228[a]);
}

void __end_critical_region(unsigned int a)
{
  LeaveCriticalSection(&DAT_0057d228[a]);
}

