/** @file

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Library/BaseLib.h>
#include <Library/NoAsanBaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/PcdLib.h>
#include <BootloaderCoreGlobal.h>
#include <Library/AsanLib.h>

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
  UINT32 ShadowOffset;
  UINT32 BlockAddr;
  UINT8  BlockSize;

  ShadowSize = ALIGN_UP(FixedPcdGet32 (PcdLoaderReservedMemSize)/9 + (1 ? FixedPcdGet32 (PcdLoaderReservedMemSize)%9 : 0), 16);

  DEBUG((DEBUG_INFO, "AsanCheckShadowMap: addr=0x%p, size=%d\n", Addr, Size));
  // Only check the access within the memory pool, as the shadow map
  // is only set for the memory pool region. Any access outside of
  // memory pool is considered as valid access to avoid false positive,
  // as ASAN is only used for early stage memory corruption detection
  // and the memory pool is the main area of concern.
  //if (((UINTN)addr < GetLoaderGlobalDataPointer()->MemPoolStart) || 
  //    (UINTN)addr + size > GetLoaderGlobalDataPointer()->StackTop) 
  if (((UINTN)Addr < 0xEF00000 - FixedPcdGet32 (PcdLoaderReservedMemSize)) || 
    (UINTN)Addr + Size > 0xEF00000 - ShadowSize) 
  {
    DEBUG((DEBUG_INFO, "ASAN out of range\n"));
    return;
  }

  //shadow_size = ALIGN_UP(FixedPcdGet32 (PcdLoaderReservedMemSize)/9 + (1 ? FixedPcdGet32 (PcdLoaderReservedMemSize)%9 : 0), 16);
  ShadowOffset = FixedPcdGet32 (PcdLoaderReservedMemSize) - ShadowSize;

  for (BlockAddr = (UINTN)Addr, BlockSize = (8 - BlockAddr%8) ;
       BlockAddr < (UINTN)Addr + Size; BlockAddr += BlockSize) 
  {
    ShadowAddr = (UINT8 *)(((UINTN)BlockAddr>>3) + ShadowOffset);

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

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_00(VOID *addr, UINTN size) {

  NoAsanZeroMem(addr, size);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f1(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF1);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f2(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF2);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f3(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF3);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f4(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF4);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f5(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF5);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f6(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF6);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f7(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF7);
}

NO_SANITIZE_ADDRESS
VOID
__asan_set_shadow_f8(VOID *addr, UINTN size) {

  NoAsanSetMem(addr, size, 0xF8);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_load1(VOID *addr) {
  AsanCheckShadowMap(addr, 1);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_load2(VOID *addr) {
  AsanCheckShadowMap(addr, 2);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_load4(VOID *addr) {
  AsanCheckShadowMap(addr, 4);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_load8(VOID *addr) {
  AsanCheckShadowMap(addr, 8);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_store1(VOID *addr) {
  AsanCheckShadowMap(addr, 1);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_store2(VOID *addr) {
  AsanCheckShadowMap(addr, 2);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_store4(VOID *addr) {
  AsanCheckShadowMap(addr, 4);
}

NO_SANITIZE_ADDRESS 
VOID 
__asan_store8(VOID *addr) {
  AsanCheckShadowMap(addr, 8);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_load1(VOID *addr) {

  AsanDebugHalt(addr, 1);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_load2(VOID *addr) {

  AsanDebugHalt(addr, 2);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_load4(VOID *addr) {
  
  AsanDebugHalt(addr, 4);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_load8(VOID *addr) {

  AsanDebugHalt(addr, 8);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_store1(VOID *addr) {

  AsanDebugHalt(addr, 1);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_store2(VOID *addr) {

  AsanDebugHalt(addr, 2);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_store4(VOID *addr) {
  
  AsanDebugHalt(addr, 4);
}

NO_SANITIZE_ADDRESS
VOID
__asan_report_store8(VOID *addr) {

  AsanDebugHalt(addr, 8);
}