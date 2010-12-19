/*
 * Copyright (c) 2003, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2007 Red Hat, Inc.
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

#include "incls/_precompiled.incl"
#include "incls/_bytecodes_zero.cpp.incl"

void Bytecodes::pd_initialize() {
#ifdef HOTSPOT_ASM
  // Because iaccess_N can trap, we must say aload_N can trap, otherwise
  // we get an assertion failure
  def(_aload_1, "aload_1", "b", NULL, T_OBJECT ,  1, true);
  def(_aload_2, "aload_2", "b", NULL, T_OBJECT ,  1, true);
  def(_aload_3, "aload_3", "b", NULL, T_OBJECT ,  1, true);

  def(_iaccess_0, "_iaccess_0", "b_jj", NULL, T_INT,  1, true, _aload_0);
  def(_iaccess_1, "_iaccess_1", "b_jj", NULL, T_INT,  1, true, _aload_1);
  def(_iaccess_2, "_iaccess_2", "b_jj", NULL, T_INT,  1, true, _aload_2);
  def(_iaccess_3, "_iaccess_3", "b_jj", NULL, T_INT,  1, true, _aload_3);

  def(_invokeresolved,   "invokeresolved",   "bjj", NULL, T_ILLEGAL, -1, true, _invokevirtual);
  def(_invokespecialresolved, "invokespecialresolved", "bjj", NULL, T_ILLEGAL, -1, true, _invokespecial);
  def(_invokestaticresolved,  "invokestaticresolved",  "bjj", NULL, T_ILLEGAL,  0, true, _invokestatic);

  def(_dmac,            "dmac",      "b_",  NULL, T_DOUBLE, -16, false, _dmul);

  def(_iload_iload,      "iload_iload",      "bi_i",NULL, T_INT, 2, false, _iload);
  def(_iload_iload_N,    "ilaod_iload_N",    "bi_", NULL, T_INT, 2, false, _iload);

  def(_iload_0_iconst_N, "iload_0_iconst_N", "b_",  NULL, T_INT, 2, false, _iload_0);
  def(_iload_1_iconst_N, "iload_1_iconst_N", "b_",  NULL, T_INT, 2, false, _iload_1);
  def(_iload_2_iconst_N, "iload_2_iconst_N", "b_",  NULL, T_INT, 2, false, _iload_2);
  def(_iload_3_iconst_N, "iload_3_iconst_N", "b_",  NULL, T_INT, 2, false, _iload_3);
  def(_iload_iconst_N,   "iload_iconst_N",   "bi_", NULL, T_INT, 2, false, _iload);

  def(_iadd_istore_N,    "iadd_istore_N",    "b_",  NULL, T_VOID, -2, false, _iadd);
  def(_isub_istore_N,    "isub_istore_N",    "b_",  NULL, T_VOID, -2, false, _isub);
  def(_iand_istore_N,    "iand_istore_N",    "b_",  NULL, T_VOID, -2, false, _iand);
  def(_ior_istore_N,     "ior_istore_N",     "b_",  NULL, T_VOID, -2, false, _ior);
  def(_ixor_istore_N,    "ixor_istore_N",    "b_",  NULL, T_VOID, -2, false, _ixor);

  def(_iadd_u4store,     "iadd_u4store",     "b_i", NULL, T_VOID, -2, false, _iadd);
  def(_isub_u4store,     "isub_u4store",     "b_i", NULL, T_VOID, -2, false, _isub);
  def(_iand_u4store,     "iand_u4store",     "b_i", NULL, T_VOID, -2, false, _iand);
  def(_ior_u4store,      "ior_u4store",      "b_i", NULL, T_VOID, -2, false, _ior);
  def(_ixor_u4store,     "ixor_u4store",     "b_i", NULL, T_VOID, -2, false, _ixor);

  def(_iload_0_iload,    "iload_0_iload",    "b_i", NULL, T_INT, 2, false, _iload_0);
  def(_iload_1_iload,    "iload_1_iload",    "b_i", NULL, T_INT, 2, false, _iload_1);
  def(_iload_2_iload,    "iload_2_iload",    "b_i", NULL, T_INT, 2, false, _iload_2);
  def(_iload_3_iload,    "iload_3_iload",    "b_i", NULL, T_INT, 2, false, _iload_3);

  def(_iload_0_iload_N,  "iload_0_iload_N",  "b_",  NULL, T_INT, 2, false, _iload_0);
  def(_iload_1_iload_N,  "iload_1_iload_N",  "b_",  NULL, T_INT, 2, false, _iload_1);
  def(_iload_2_iload_N,  "iload_2_iload_N",  "b_",  NULL, T_INT, 2, false, _iload_2);
  def(_iload_3_iload_N,  "iload_3_iload_N",  "b_",  NULL, T_INT, 2, false, _iload_3);

#endif // HOTSPOT_ASM
}
