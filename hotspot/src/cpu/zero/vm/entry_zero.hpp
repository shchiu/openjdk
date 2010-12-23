/*
 * Copyright (c) 2003, 2007, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2008, 2009, 2010 Red Hat, Inc.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 *
 */
#include <sys/mman.h>
#include <errno.h>

class ZeroEntry {
 public:
  ZeroEntry() {
    ShouldNotCallThis();
  }

 private:
  address _entry_point;

 public:
  address entry_point() const {
    return _entry_point;
  }
  void set_entry_point(address entry_point) {
    _entry_point = entry_point;
  }

 private:
  typedef int (*NormalEntryFunc)(methodOop method,
                                 intptr_t  base_pc,
                                 TRAPS);
  typedef int (*OSREntryFunc)(methodOop method,
                              address   osr_buf,
                              intptr_t  base_pc,
                              TRAPS);

 public:
  void invoke(methodOop method, TRAPS) const {
    maybe_deoptimize(
      ((NormalEntryFunc) entry_point())(method, (intptr_t) this, THREAD),
      THREAD);
  }
  void invoke_osr(methodOop method, address osr_buf, TRAPS) const {
    maybe_deoptimize(
      ((OSREntryFunc) entry_point())(method, osr_buf, (intptr_t) this, THREAD),
      THREAD);

/*	asm volatile (
		"mov    -0x8(%%rbp),%%rdx	\n"
		"mov    -0x20(%%rbp),%%rcx	\n"
		"mov    -0x18(%%rbp),%%rsi	\n"
		"mov    -0x10(%%rbp),%%rdi	\n"
		::
		);

	//allocate a space for compiled code.
	void *p = mmap((char*)0x90000000, 4096, PROT_EXEC|PROT_READ|PROT_WRITE ,
		MAP_PRIVATE | MAP_32BIT | MAP_ANONYMOUS, -1 ,0 );
	
	void *entry = entry_point();
	if( p == MAP_FAILED )
		perror("mmap");
	else {
		if( memcpy( p, entry, 4096 ) < 0 )
			perror("memcpy");
*/	}

 private:
  static void maybe_deoptimize(int deoptimized_frames, TRAPS) {
    if (deoptimized_frames)
      CppInterpreter::main_loop(deoptimized_frames - 1, THREAD);
  }

 public:
  static ByteSize entry_point_offset() {
    return byte_offset_of(ZeroEntry, _entry_point);
  }
};
