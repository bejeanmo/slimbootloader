/** @file

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Base.h>
#include <Library/BaseLib.h>
#include <Library/NoAsanBaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <BootloaderCoreGlobal.h>
#include <Library/AsanLib.h>
#include <Library/PcdLib.h>

BOOLEAN outer = 0;

VOID
AsanInit(VOID) {
  outer = 1;
  // MS compiler uses fixed shadow region of 0x30000000 - 0x3FFFFFFF for 32-bit
  //PcdSet64S(PcdAsanShadowBase, 0x30000000);
}

NO_SANITIZE_ADDRESS
VOID
AsanDebugHalt(VOID* addr, UINTN size) {
  DEBUG((DEBUG_ERROR, "SUMMARY: AddressSanitizer: overflow at address 0x%p, size %d\n", addr, size));

  DEBUG((DEBUG_ERROR, "Shadow bytes around the buggy address:\n"));

  CpuDeadLoop();
  
}

NO_SANITIZE_ADDRESS
VOID
AsanCheckShadowMap(VOID* Addr, UINTN Size) {
  UINT8 *ShadowAddr;
  UINT32 ShadowSize;
  UINT64 ShadowOffset;
  UINTN  BlockAddr;
  UINT8  BlockSize;

  ShadowSize = ALIGN_UP(FixedPcdGet32 (PcdLoaderReservedMemSize)/9 + (1 ? FixedPcdGet32 (PcdLoaderReservedMemSize)%9 : 0), 16);

  //DEBUG((DEBUG_INFO, "AsanCheckShadowMap: addr=0x%p, size=%d\n", Addr, Size));
  // Only check the access within the memory pool, Any access outside of
  // memory pool is considered as valid access to avoid false positive,
  // as ASAN is only used for early stage memory corruption detection
  // and the memory pool is the main area of concern.
  if (((UINTN)Addr < 0xEF00000 - FixedPcdGet32 (PcdLoaderReservedMemSize)) || 
    (UINTN)Addr + Size > 0xEF00000) 
  {
    //DEBUG((DEBUG_INFO, "ASAN out of range\n"));
    return;
  }

  //shadow_size = ALIGN_UP(FixedPcdGet32 (PcdLoaderReservedMemSize)/9 + (1 ? FixedPcdGet32 (PcdLoaderReservedMemSize)%9 : 0), 16);
  ShadowOffset = 0x30000000;//PcdGet64(PcdAsanShadowBase);

  for (BlockAddr = (UINTN)Addr, BlockSize = (8 - BlockAddr%8) ;
       BlockAddr < (UINTN)Addr + Size; BlockAddr += BlockSize) 
  {
    ShadowAddr = (UINT8 *)(((UINTN)BlockAddr>>3) + (UINTN)ShadowOffset);

    if (*ShadowAddr > (((UINTN)BlockAddr & 0x7) + BlockSize)) {
      AsanDebugHalt(Addr, Size);
    }
    BlockSize = MIN((UINT8)8, (UINT8)((UINTN)Addr + Size - BlockAddr));
  }
}

NO_SANITIZE_ADDRESS
VOID
__asan_memcpy(VOID *Dest, VOID *Src, UINTN Size) {

  AsanCheckShadowMap(Dest, Size);
  AsanCheckShadowMap(Src, Size);
  NoAsanCopyMem(Dest, Src, Size);
}

#define ASAN_LOAD_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_load##value(VOID *addr) { \
    AsanCheckShadowMap(addr, value); \
  }

ASAN_LOAD_FUNC(1)
ASAN_LOAD_FUNC(2)
ASAN_LOAD_FUNC(4)
ASAN_LOAD_FUNC(8)

#define ASAN_STORE_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_store##value(VOID *addr) { \
    AsanCheckShadowMap(addr, value); \
  }

ASAN_STORE_FUNC(1)
ASAN_STORE_FUNC(2)
ASAN_STORE_FUNC(4)
ASAN_STORE_FUNC(8)

#define ASAN_REPORT_LOAD_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_report_load##value(VOID *addr) { \
    AsanDebugHalt(addr, value); \
  }

ASAN_REPORT_LOAD_FUNC(1)
ASAN_REPORT_LOAD_FUNC(2)
ASAN_REPORT_LOAD_FUNC(4)
ASAN_REPORT_LOAD_FUNC(8)

#define ASAN_REPORT_STORE_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_report_store##value(VOID *addr) { \
    AsanDebugHalt(addr, value); \
  }

ASAN_REPORT_STORE_FUNC(1)
ASAN_REPORT_STORE_FUNC(2)
ASAN_REPORT_STORE_FUNC(4)
ASAN_REPORT_STORE_FUNC(8)

#define ASAN_SET_SHADOW_FUNC_HEX(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_set_shadow_##value(VOID *addr, UINTN size) { \
    NoAsanSetMem(addr, size, 0x##value); \
  }

ASAN_SET_SHADOW_FUNC_HEX(00)
ASAN_SET_SHADOW_FUNC_HEX(f1)
ASAN_SET_SHADOW_FUNC_HEX(f2)
ASAN_SET_SHADOW_FUNC_HEX(f3)
ASAN_SET_SHADOW_FUNC_HEX(f4)
ASAN_SET_SHADOW_FUNC_HEX(f5)
ASAN_SET_SHADOW_FUNC_HEX(f6)
ASAN_SET_SHADOW_FUNC_HEX(f7)
ASAN_SET_SHADOW_FUNC_HEX(f8)
ASAN_SET_SHADOW_FUNC_HEX(f9)
ASAN_SET_SHADOW_FUNC_HEX(fa)
ASAN_SET_SHADOW_FUNC_HEX(fb)
ASAN_SET_SHADOW_FUNC_HEX(fc)
ASAN_SET_SHADOW_FUNC_HEX(fd)
ASAN_SET_SHADOW_FUNC_HEX(fe)
ASAN_SET_SHADOW_FUNC_HEX(ff)

NO_SANITIZE_ADDRESS
VOID
__asan_memset(VOID *addr, int value, UINTN size) {
  AsanCheckShadowMap(addr, size);
  NoAsanSetMem(addr, size, (UINT8)value);
}
