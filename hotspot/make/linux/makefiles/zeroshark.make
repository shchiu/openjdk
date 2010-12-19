#
# Copyright (c) 2003, 2005, Oracle and/or its affiliates. All rights reserved.
# Copyright 2007, 2008 Red Hat, Inc.
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
#
# This code is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License version 2 only, as
# published by the Free Software Foundation.
#
# This code is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# version 2 for more details (a copy is included in the LICENSE file that
# accompanied this code).
#
# You should have received a copy of the GNU General Public License version
# 2 along with this work; if not, write to the Free Software Foundation,
# Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
# or visit www.oracle.com if you need additional information or have any
# questions.
#
#

# Setup common to Zero (non-Shark) and Shark versions of VM

ifeq ($(ZERO_LIBARCH),arm)

Obj_Files += asm_helper.o
Obj_Files += cppInterpreter_arm.o
Obj_Files += thumb2.o

#XXX disabled until it has the updated frame anchor code (PR icedteopenjdk.orig/hotspot/323)
#XXX and the updated calling convention for deopt (PR icedteopenjdk.orig/hotspot/484)
#CFLAGS += -DHOTSPOT_ASM

%.o: %.S
	@echo Assembling $<
	$(QUIETLY) $(REMOVE_TARGET)
	$(COMPILE.CC) -o $@ $< $(COMPILE_DONE)

cppInterpreter_arm.o:	offsets_arm.s bytecodes_arm.s
thumb2.o:		offsets_arm.s

offsets_arm.s:	mkoffsets
	@echo Generating assembler offsets
	./mkoffsets > $@

bytecodes_arm.s: bytecodes_arm.def mkbc
	@echo Generatine ARM assembler bytecode sequences
	$(CC_COMPILE) -E -x c++ - < $< | ./mkbc - $@ $(COMPILE_DONE)

mkbc:	$(GAMMADIR)/tools/mkbc.c
	@echo Compiling mkbc tool
	$(CC_COMPILE) -o $@ $< $(COMPILE_DONE)

mkoffsets:	asm_helper.cpp
	@echo Compiling offset generator
	$(QUIETLY) $(REMOVE_TARGET)
	$(CC_COMPILE) -DSTATIC_OFFSETS -o $@ $< $(COMPILE_DONE)

endif

# The copied fdlibm routines in sharedRuntimeTrig.o must not be optimized
OPT_CFLAGS/sharedRuntimeTrig.o = $(OPT_CFLAGS/NOOPT)
# The copied fdlibm routines in sharedRuntimeTrans.o must not be optimized
OPT_CFLAGS/sharedRuntimeTrans.o = $(OPT_CFLAGS/NOOPT)

# Specify that the CPU is little endian, if necessary
ifeq ($(ZERO_ENDIANNESS), little)
  CFLAGS += -DVM_LITTLE_ENDIAN
endif

# Specify that the CPU is 64 bit, if necessary
ifeq ($(ARCH_DATA_MODEL), 64)
  CFLAGS += -D_LP64=1
endif

OPT_CFLAGS/compactingPermGenGen.o = -O1
