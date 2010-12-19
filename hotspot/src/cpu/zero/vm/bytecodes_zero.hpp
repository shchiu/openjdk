/*
 * Copyright (c) 1997, 2007, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2009 Red Hat, Inc.
 * Copyright 2009 Edward Nevill
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

#ifdef HOTSPOT_ASM
#define _iaccess_0      ((Bytecodes::Code)0xdb)
#define _iaccess_1      ((Bytecodes::Code)0xdc)
#define _iaccess_2      ((Bytecodes::Code)0xdd)
#define _iaccess_3      ((Bytecodes::Code)0xde)

#define _invokeresolved         ((Bytecodes::Code)0xdf)
#define _invokespecialresolved  ((Bytecodes::Code)0xe0)
#define _invokestaticresolved   ((Bytecodes::Code)0xe1)

#define _iload_iload    ((Bytecodes::Code)0xe3)
#define _iload_iload_N  ((Bytecodes::Code)0xe4)

#define _dmac           ((Bytecodes::Code)0xe6)

        _iload_0_iconst_N       ,       // 231
        _iload_1_iconst_N       ,       // 232
        _iload_2_iconst_N       ,       // 233
        _iload_3_iconst_N       ,       // 234
        _iload_iconst_N         ,       // 235
        _iadd_istore_N          ,       // 236
        _isub_istore_N          ,       // 237
        _iand_istore_N          ,       // 238
        _ior_istore_N           ,       // 239
        _ixor_istore_N          ,       // 240
        _iadd_u4store           ,       // 241
        _isub_u4store           ,       // 242
        _iand_u4store           ,       // 243
        _ior_u4store            ,       // 244
        _ixor_u4store           ,       // 245
        _iload_0_iload          ,       // 246
        _iload_1_iload          ,       // 247
        _iload_2_iload          ,       // 248
        _iload_3_iload          ,       // 249
        _iload_0_iload_N        ,       // 250
        _iload_1_iload_N        ,       // 251
        _iload_2_iload_N        ,       // 252
        _iload_3_iload_N        ,       // 253
#endif // HOTSPOT_ASM
