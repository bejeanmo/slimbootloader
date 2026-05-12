/** @file

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/
#include <Base.h>
#include <Library/AsanLib.h>
#include <Library/BaseMemoryLib.h>

VOID
AsanInit(VOID) {
  return;
}

NO_SANITIZE_ADDRESS
VOID
AsanCheckShadowMap(VOID* Addr, UINTN Size) {
  return;
}

NO_SANITIZE_ADDRESS
VOID
__asan_memcpy(VOID *Dest, VOID *Src, UINTN Size) {

  CopyMem(Dest, Src, Size);
}

#define ASAN_LOAD_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_load##value(VOID *addr) { \
    return; \
  }

ASAN_LOAD_FUNC(1)
ASAN_LOAD_FUNC(2)
ASAN_LOAD_FUNC(4)
ASAN_LOAD_FUNC(8)

#define ASAN_STORE_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_store##value(VOID *addr) { \
    return; \
  }

ASAN_STORE_FUNC(1)
ASAN_STORE_FUNC(2)
ASAN_STORE_FUNC(4)
ASAN_STORE_FUNC(8)

#define ASAN_REPORT_LOAD_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_report_load##value(VOID *addr) { \
    return; \
  }

ASAN_REPORT_LOAD_FUNC(1)
ASAN_REPORT_LOAD_FUNC(2)
ASAN_REPORT_LOAD_FUNC(4)
ASAN_REPORT_LOAD_FUNC(8)

#define ASAN_REPORT_STORE_FUNC(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_report_store##value(VOID *addr) { \
    return; \
  }

ASAN_REPORT_STORE_FUNC(1)
ASAN_REPORT_STORE_FUNC(2)
ASAN_REPORT_STORE_FUNC(4)
ASAN_REPORT_STORE_FUNC(8)

#define ASAN_SET_SHADOW_FUNC_HEX(value) \
  NO_SANITIZE_ADDRESS \
  VOID \
  __asan_set_shadow_##value(VOID *addr, UINTN size) { \
    return; \
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

  SetMem(addr, size, (UINT8)value);
}
