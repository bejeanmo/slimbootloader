/** @file

  Copyright (c) 2026, Intel Corporation. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent

**/

#ifndef __ASAN_LIB_H__
#define __ASAN_LIB_H__

#ifdef __SANITIZE_ADDRESS__
// no_sanitize_address is only defined when compiling with MSVC AddressSanitizer.
// Guard against this by checking if `__SANITIZE_ADDRESS__` is defined.
#define NO_SANITIZE_ADDRESS __declspec(no_sanitize_address)
#else
#define NO_SANITIZE_ADDRESS
#endif

#endif // __ASAN_LIB_H__