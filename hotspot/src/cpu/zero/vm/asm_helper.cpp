/*
 * Copyright 2009, 2010 Edward Nevill
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
 */

#define	ARCH_THUMBEE	(1<<16)
#define ARCH_VFP	(1<<17)
#define ARCH_CLZ	(1<<18)

#ifndef STATIC_OFFSETS

#include "incls/_bytecodeInterpreter.cpp.incl"

#include <linux/auxvec.h>
#include <asm/hwcap.h>

#define VECBUFF_SIZE 64

extern "C" unsigned hwcap(void)
{
  int fd;
  unsigned vecs[VECBUFF_SIZE];
  unsigned *p;
  int i, n;
  unsigned rc = 0;
  unsigned arch = 4;
 
  fd = open("/proc/self/auxv", O_RDONLY);
  if (fd < 0) return 0;
  do {
    n = read(fd, vecs, VECBUFF_SIZE * sizeof(unsigned));
    p = vecs;
    i = n/8;
    while (--i >= 0) {
      unsigned tag = *p++;
      unsigned value = *p++;
      if (tag == 0) goto fini;
      if (tag == AT_HWCAP) {
	if (value & HWCAP_THUMBEE) rc |= ARCH_THUMBEE;
	if (value & HWCAP_VFP) rc |= ARCH_VFP;
      } else if (tag == AT_PLATFORM) {
	const char *s = (const char *)value;
	int c;

	if (*s++ == 'v') {
	  arch = 0;
	  while ((isdigit)(c = *s++)) arch = arch * 10 + c - '0';
	}
      }
    }
  } while (n == VECBUFF_SIZE * sizeof(unsigned));
fini:
  close(fd);
//  printf("arch = %d, rc = 0x%08x\n", arch, rc);
  if (arch >= 5) rc |= ARCH_CLZ;
  if (arch >= 7) rc |= ARCH_THUMBEE;
  return rc | (1<<arch);
}

/* Thease functions allow the ASM interpreter to call CPP virtual functions.
 * Otherwise the ASM interpreter has to grup around in the VTABLE which is
 * not very portable.
 */
extern "C" bool JavaThread_is_lock_owned(JavaThread *r0, address r1)
{
	return r0->is_lock_owned(r1);
}

extern "C" HeapWord **CollectedHeap_top_addr(CollectedHeap *r0)
{
	return r0->top_addr();
}

extern "C" HeapWord **CollectedHeap_end_addr(CollectedHeap *r0)
{
	return r0->end_addr();
}

extern "C" char *SharedRuntime_generate_class_cast_message(const char *name, const char *klass)
{
	return SharedRuntime::generate_class_cast_message(name, klass);
}

#define HELPER_THROW(thread, name, msg) Exceptions::_throw_msg(thread, __FILE__, __LINE__, name, msg)

class VMStructs {
public:
	static inline klassOop klass_at_addr(constantPoolOop constants, u2 index) {
	  return (klassOop) *constants->obj_at_addr(index);
	}
};

extern "C" oop Helper_new(interpreterState istate, unsigned index)
{
    JavaThread *thread = istate->thread();

    constantPoolOop constants = istate->method()->constants();
    oop result = NULL;
    if (!constants->tag_at(index).is_unresolved_klass()) {
      // Make sure klass is initialized and doesn't have a finalizer
      oop entry = VMStructs::klass_at_addr(constants, index);
      klassOop k_entry = (klassOop) entry;
      instanceKlass* ik = (instanceKlass*) k_entry->klass_part();
      if ( ik->is_initialized() && ik->can_be_fastpath_allocated() ) {
	size_t obj_size = ik->size_helper();
	// If the TLAB isn't pre-zeroed then we'll have to do it
	bool need_zero = !ZeroTLAB;
	if (UseTLAB) {
	  result = (oop) thread->tlab().allocate(obj_size);
	}
	if (result == NULL) {
	  need_zero = true;
	  // Try allocate in shared eden
    retry:
	  HeapWord* compare_to = *Universe::heap()->top_addr();
	  HeapWord* new_top = compare_to + obj_size;
	  if (new_top <= *Universe::heap()->end_addr()) {
	    if (Atomic::cmpxchg_ptr(new_top, Universe::heap()->top_addr(), compare_to) != compare_to) {
	      goto retry;
	    }
	    result = (oop) compare_to;
	  }
	}
	if (result != NULL) {
	  // Initialize object (if nonzero size and need) and then the header
	  if (need_zero ) {
	    HeapWord* to_zero = (HeapWord*) result + sizeof(oopDesc) / oopSize;
	    obj_size -= sizeof(oopDesc) / oopSize;
	    if (obj_size > 0 ) {
	      memset(to_zero, 0, obj_size * HeapWordSize);
	    }
	  }
	  if (UseBiasedLocking) {
	    result->set_mark(ik->prototype_header());
	  } else {
	    result->set_mark(markOopDesc::prototype());
	  }
	  result->set_klass_gap(0);
	  result->set_klass(k_entry);
	  return result;
	}
      }
    }
    // Slow case allocation
    InterpreterRuntime::_new(thread, istate->method()->constants(), index);
    result = thread->vm_result();
    thread->set_vm_result(NULL);
    return result;
}

extern "C" int Helper_instanceof(interpreterState istate, unsigned index, oop tos)
{
    if (tos == NULL) return 0;

    // Constant pool may have actual klass or unresolved klass. If it is
    // unresolved we must resolve it
    if (istate->method()->constants()->tag_at(index).is_unresolved_klass()) {
      InterpreterRuntime::quicken_io_cc(istate->thread());
      if (istate->thread()->has_pending_exception()) return 0;
    }
    klassOop klassOf = VMStructs::klass_at_addr(istate->method()->constants(), index);
    klassOop objKlassOop = tos->klass();
    //
    // Check for compatibilty. This check must not GC!!
    // Seems way more expensive now that we must dispatch
    //
    return objKlassOop == klassOf || objKlassOop->klass_part()->is_subtype_of(klassOf);
}

extern "C" oop Helper_checkcast(interpreterState istate, unsigned index, oop tos)
{
    if (tos == NULL) return NULL;

    // Constant pool may have actual klass or unresolved klass. If it is
    // unresolved we must resolve it
    if (istate->method()->constants()->tag_at(index).is_unresolved_klass()) {
      oop except_oop;
      InterpreterRuntime::quicken_io_cc(istate->thread());
      if (except_oop = istate->thread()->pending_exception()) return except_oop;
    }
    klassOop klassOf = VMStructs::klass_at_addr(istate->method()->constants(), index);
    klassOop objKlassOop = tos->klass(); //ebx
    //
    // Check for compatibilty. This check must not GC!!
    // Seems way more expensive now that we must dispatch
    //
    if (objKlassOop != klassOf && !objKlassOop->klass_part()->is_subtype_of(klassOf)) {
      ResourceMark rm(istate->thread());
      const char* objName = Klass::cast(objKlassOop)->external_name();
      const char* klassName = Klass::cast(klassOf)->external_name();
      char* message = SharedRuntime::generate_class_cast_message(objName, klassName);
      ThreadInVMfromJava trans(istate->thread());
      HELPER_THROW(istate->thread(), vmSymbols::java_lang_ClassCastException(), message);
    }
    return istate->thread()->pending_exception();
}

extern "C" oop Helper_aastore(interpreterState istate, oop value, int index, arrayOop arrayref)
{
    if (arrayref == NULL) {
      ThreadInVMfromJava trans(istate->thread());
      HELPER_THROW(istate->thread(), vmSymbols::java_lang_NullPointerException(), "");
    } else if ((uint32_t)index >= (uint32_t)arrayref->length()) {
      char message[jintAsStringSize];
      sprintf(message, "%d", index);
      HELPER_THROW(istate->thread(), vmSymbols::java_lang_ArrayIndexOutOfBoundsException(), message);
    } else {
      if (value != NULL) {
	/* Check assignability of value into arrayref */
	klassOop rhsKlassOop = value->klass(); // EBX (subclass)
	klassOop elemKlassOop = ((objArrayKlass*) arrayref->klass()->klass_part())->element_klass();
	//
	// Check for compatibilty. This check must not GC!!
	// Seems way more expensive now that we must dispatch
	//
	if (rhsKlassOop != elemKlassOop && !rhsKlassOop->klass_part()->is_subtype_of(elemKlassOop)) {
	  HELPER_THROW(istate->thread(), vmSymbols::java_lang_ArrayStoreException(), "");
	  goto handle_exception;
	}
      }
      oop* elem_loc = (oop*)(((address) arrayref->base(T_OBJECT)) + index * sizeof(oop));
      // *(oop*)(((address) arrayref->base(T_OBJECT)) + index * sizeof(oop)) = value;
      *elem_loc = value;
      // Mark the card
      BarrierSet* bs = Universe::heap()->barrier_set();
      static volatile jbyte* _byte_map_base = (volatile jbyte*)(((CardTableModRefBS*)bs)->byte_map_base);
      OrderAccess::release_store(&_byte_map_base[(uintptr_t)elem_loc >> CardTableModRefBS::card_shift], 0);
    }
handle_exception:
    return istate->thread()->pending_exception();
}

extern "C" void Helper_aputfield(oop obj)
{
      BarrierSet* bs = Universe::heap()->barrier_set();
      static volatile jbyte* _byte_map_base = (volatile jbyte*)(((CardTableModRefBS*)bs)->byte_map_base);
      OrderAccess::release_store(&_byte_map_base[(uintptr_t)obj >> CardTableModRefBS::card_shift], 0);
}

extern "C" oop Helper_synchronized_enter(JavaThread *thread, BasicObjectLock *mon)
{
    BasicLock *lock = mon->lock();
    markOop displaced = lock->displaced_header();

    if (thread->is_lock_owned((address)displaced->clear_lock_bits()))
      lock->set_displaced_header(NULL);
    else
      InterpreterRuntime::monitorenter(thread, mon);
    return thread->pending_exception();
}

extern "C" oop Helper_synchronized_exit(JavaThread *thread, BasicObjectLock *mon)
{
    {
      HandleMark __hm(thread);
      if (mon->obj() == NULL)
	InterpreterRuntime::throw_illegal_monitor_state_exception(thread);
      else
        InterpreterRuntime::monitorexit(thread, mon);
    }
    return thread->pending_exception();
}

extern "C" oop Helper_SafePoint(JavaThread *thread)
{
    {
      HandleMarkCleaner __hmc(thread);
    }
    SafepointSynchronize::block(thread);
    return thread->pending_exception();
}

extern "C" void Helper_RaiseArrayBoundException(JavaThread *thread, int index)
{
  char message[jintAsStringSize];
  sprintf(message, "%d", index);
  {
       ThreadInVMfromJava trans(thread);
       Exceptions::_throw_msg(thread, "[Bytecoce Interpreter]", 99,
			vmSymbols::java_lang_ArrayIndexOutOfBoundsException(), message);
  }
}

extern "C" void Helper_Raise(JavaThread *thread, symbolOopDesc *name, char const *msg)
{
   ThreadInVMfromJava trans(thread);
   Exceptions::_throw_msg(thread, "[Bytecoce Interpreter]", 99, name, msg);
}

extern "C" void Helper_RaiseIllegalMonitorException(JavaThread *thread)
{
    HandleMark __hm(thread);
    thread->clear_pending_exception();
    InterpreterRuntime::throw_illegal_monitor_state_exception(thread);
}

extern "C" address Helper_HandleException(interpreterState istate, JavaThread *thread)
{
    HandleMarkCleaner __hmc(thread);
    Handle except_oop(thread, thread->pending_exception());
    HandleMark __hm(thread);
    intptr_t continuation_bci;
    intptr_t *topOfStack;
    address pc;

    thread->clear_pending_exception();
    continuation_bci = (intptr_t)InterpreterRuntime::exception_handler_for_exception(thread, except_oop());
    except_oop = (oop) thread->vm_result();
    thread->set_vm_result(NULL);
    if (continuation_bci >= 0) {
      topOfStack = (intptr_t *)istate->stack();
      *topOfStack-- = (intptr_t)except_oop();
      istate->set_stack(topOfStack);
      pc = istate->method()->code_base() + continuation_bci;
#if 0
        tty->print_cr("Exception <%s> (" INTPTR_FORMAT ")", Klass::cast(except_oop->klass())->external_name(), except_oop());
        tty->print_cr(" thrown in interpreter method <%s>", istate->method()->name_and_sig_as_C_string());
        tty->print_cr(" at bci %d, continuing at %d for thread " INTPTR_FORMAT,
                      pc - (intptr_t)istate->method()->code_base(),
                      continuation_bci, thread);
#endif
      return pc;
    }
#if 0
      tty->print_cr("Exception <%s> (" INTPTR_FORMAT ")", Klass::cast(except_oop->klass())->external_name(), except_oop());
      tty->print_cr(" thrown in interpreter method <%s>", istate->method()->name_and_sig_as_C_string());
      tty->print_cr(" at bci %d, unwinding for thread " INTPTR_FORMAT,
                    pc  - (intptr_t) istate->method()->code_base(),
                    thread);
#endif
    thread->set_pending_exception(except_oop(), NULL, 0);
    return 0;
}

#endif // STATIC_OFFSETS

#ifdef STATIC_OFFSETS

#include "incls/_precompiled.incl"

class VMStructs {
public:
	static void print_vm_offsets(void);
};

#define outfile	stdout

void print_def(const char *s, int v)
{
	fprintf(outfile, "#undef %-40s\n", s);
	fprintf(outfile, "#define %-40s 0x%02x\n", s, v);
}

void nl(void)
{
	fputc('\n', outfile);
}

// ZeroFrame is not friends with VMStructs, but it is with ZeroStackPrinter
class ZeroStackPrinter {
public:
  static void print_vm_offsets(void);
};

void ZeroStackPrinter::print_vm_offsets(void)
{
    print_def("INTERPRETER_FRAME", ZeroFrame::INTERPRETER_FRAME);
}

void VMStructs::print_vm_offsets(void)
{
  print_def("ISTATE_THREAD",    offset_of(BytecodeInterpreter, _thread));
  print_def("ISTATE_BCP",       offset_of(BytecodeInterpreter, _bcp));
  print_def("ISTATE_LOCALS",    offset_of(BytecodeInterpreter, _locals));
  print_def("ISTATE_CONSTANTS", offset_of(BytecodeInterpreter, _constants));
  print_def("ISTATE_METHOD",    offset_of(BytecodeInterpreter, _method));
  print_def("ISTATE_STACK",     offset_of(BytecodeInterpreter, _stack));
  print_def("ISTATE_MSG",       offset_of(BytecodeInterpreter, _msg));
  print_def("ISTATE_OOP_TEMP",	offset_of(BytecodeInterpreter, _oop_temp));
  print_def("ISTATE_STACK_BASE",offset_of(BytecodeInterpreter, _stack_base));
  print_def("ISTATE_STACK_LIMIT",offset_of(BytecodeInterpreter, _stack_limit));
  print_def("ISTATE_MONITOR_BASE",offset_of(BytecodeInterpreter, _monitor_base));
  print_def("ISTATE_SELF_LINK",	offset_of(BytecodeInterpreter, _self_link));
  print_def("ISTATE_FRAME_TYPE", sizeof(BytecodeInterpreter) + 0);
  print_def("ISTATE_NEXT_FRAME", sizeof(BytecodeInterpreter) + 4);
  print_def("FRAME_SIZE", sizeof(BytecodeInterpreter) + 8);
  nl();
  ZeroStackPrinter::print_vm_offsets();
  nl();
  print_def("THREAD_PENDING_EXC", offset_of(JavaThread, _pending_exception));
  print_def("THREAD_SUSPEND_FLAGS", offset_of(JavaThread, _suspend_flags));
  print_def("THREAD_ACTIVE_HANDLES", offset_of(JavaThread, _active_handles));
  print_def("THREAD_LAST_HANDLE_MARK", offset_of(JavaThread, _last_handle_mark));
  print_def("THREAD_TLAB_TOP", offset_of(JavaThread, _tlab) + offset_of(ThreadLocalAllocBuffer, _top));
  print_def("THREAD_TLAB_END", offset_of(JavaThread, _tlab) + offset_of(ThreadLocalAllocBuffer, _end));
  print_def("THREAD_RESOURCEAREA", offset_of(JavaThread, _resource_area));
  print_def("THREAD_HANDLE_AREA", offset_of(JavaThread, _handle_area));
  print_def("THREAD_STACK_BASE", offset_of(JavaThread, _stack_base));
  print_def("THREAD_STACK_SIZE", offset_of(JavaThread, _stack_size));
  print_def("THREAD_LAST_JAVA_SP", offset_of(JavaThread, _anchor) + offset_of(JavaFrameAnchor, _last_Java_sp));
  print_def("THREAD_JNI_ENVIRONMENT", offset_of(JavaThread, _jni_environment));
  print_def("THREAD_VM_RESULT", offset_of(JavaThread, _vm_result));
  print_def("THREAD_STATE", offset_of(JavaThread, _thread_state));
  print_def("THREAD_DO_NOT_UNLOCK", offset_of(JavaThread, _do_not_unlock_if_synchronized));

  print_def("THREAD_JAVA_STACK_BASE", offset_of(JavaThread, _zero_stack) + in_bytes(ZeroStack::base_offset()));
  print_def("THREAD_JAVA_SP", offset_of(JavaThread, _zero_stack) + in_bytes(ZeroStack::sp_offset()));
  print_def("THREAD_TOP_ZERO_FRAME", offset_of(JavaThread, _top_zero_frame));
  print_def("THREAD_SPECIALRUNTIMEEXITCONDITION", offset_of(JavaThread, _special_runtime_exit_condition));
  nl();
  print_def("_thread_external_suspend",	Thread::_external_suspend);
  print_def("_thread_ext_suspended",	Thread::_ext_suspended);
  print_def("_thread_deopt_suspend",	Thread::_deopt_suspend);
  nl();
  print_def("METHOD_CONSTMETHOD", offset_of(methodOopDesc, _constMethod));
  print_def("METHOD_CONSTANTS", offset_of(methodOopDesc, _constants));
  print_def("METHOD_METHODDATA", offset_of(methodOopDesc, _method_data));
  print_def("METHOD_INVOKECOUNT", offset_of(methodOopDesc, _interpreter_invocation_count));
  print_def("METHOD_ACCESSFLAGS", offset_of(methodOopDesc, _access_flags));
  print_def("METHOD_VTABLEINDEX", offset_of(methodOopDesc, _vtable_index));
  print_def("METHOD_RESULTINDEX", offset_of(methodOopDesc, _result_index));
  print_def("METHOD_METHODSIZE", offset_of(methodOopDesc, _method_size));
  print_def("METHOD_MAXSTACK", offset_of(methodOopDesc, _max_stack));
  print_def("METHOD_MAXLOCALS", offset_of(methodOopDesc, _max_locals));
  print_def("METHOD_SIZEOFPARAMETERS", offset_of(methodOopDesc, _size_of_parameters));
  print_def("METHOD_INVOCATIONCOUNTER", offset_of(methodOopDesc, _invocation_counter));
  print_def("METHOD_BACKEDGECOUNTER", offset_of(methodOopDesc, _backedge_counter));
  print_def("METHOD_FROM_INTERPRETED", offset_of(methodOopDesc, _from_interpreted_entry));
  // ECN: These two appear to be just tagged onto the end of the class
  print_def("METHOD_NATIVEHANDLER", sizeof(methodOopDesc));
  print_def("METHOD_SIGNATUREHANDLER", sizeof(methodOopDesc)+4);
  nl();
  print_def("CONSTMETHOD_CODESIZE", offset_of(constMethodOopDesc, _code_size));
  print_def("CONSTMETHOD_CODEOFFSET", sizeof(constMethodOopDesc));
  nl();
  print_def("JNIHANDLEBLOCK_TOP", offset_of(JNIHandleBlock, _top));
  nl();
  print_def("KLASS_PART", klassOopDesc::klass_part_offset_in_bytes());
  print_def("KLASS_ACCESSFLAGS", offset_of(Klass, _access_flags));
  print_def("KLASS_JAVA_MIRROR", offset_of(Klass, _java_mirror));
  print_def("INSTANCEKLASS_INITSTATE", offset_of(instanceKlass, _init_state));
  print_def("INSTANCEKLASS_VTABLE_LEN", offset_of(instanceKlass, _vtable_len));
  print_def("INSTANCEKLASS_ITABLE_LEN", offset_of(instanceKlass, _itable_len));
  print_def("INSTANCEKLASS_VTABLE_OFFSET", instanceKlass::vtable_start_offset() * sizeof(int *));
  print_def("OBJARRAYKLASS_ELEMENTKLASS", offset_of(objArrayKlass, _element_klass));
  nl();
  print_def("CONSTANTPOOL_TAGS", offset_of(constantPoolOopDesc, _tags));
  print_def("CONSTANTPOOL_CACHE", offset_of(constantPoolOopDesc, _cache));
  print_def("CONSTANTPOOL_POOL_HOLDER", offset_of(constantPoolOopDesc, _pool_holder));
  print_def("CONSTANTPOOL_BASE", sizeof(constantPoolOopDesc));
  nl();
  print_def("CP_OFFSET", in_bytes(constantPoolCacheOopDesc::base_offset()));
  nl();
  print_def("BASE_OFFSET_BYTE", arrayOopDesc::base_offset_in_bytes(T_BYTE));
  print_def("BASE_OFFSET_SHORT", arrayOopDesc::base_offset_in_bytes(T_SHORT));
  print_def("BASE_OFFSET_WORD", arrayOopDesc::base_offset_in_bytes(T_INT));
  print_def("BASE_OFFSET_LONG", arrayOopDesc::base_offset_in_bytes(T_LONG));
  nl();
  print_def("SIZEOF_HANDLEMARK", sizeof(HandleMark));
}

int main(void)
{
	print_def("ARCH_VFP",			ARCH_VFP);
	print_def("ARCH_THUMBEE",		ARCH_THUMBEE);
	print_def("ARCH_CLZ",			ARCH_CLZ);
	nl();
	print_def("JVM_CONSTANT_Utf8",		JVM_CONSTANT_Utf8);
	print_def("JVM_CONSTANT_Unicode",	JVM_CONSTANT_Unicode);
	print_def("JVM_CONSTANT_Integer",	JVM_CONSTANT_Integer);
	print_def("JVM_CONSTANT_Float",		JVM_CONSTANT_Float);
	print_def("JVM_CONSTANT_Long",		JVM_CONSTANT_Long);
	print_def("JVM_CONSTANT_Double",	JVM_CONSTANT_Double);
	print_def("JVM_CONSTANT_Class",		JVM_CONSTANT_Class);
	print_def("JVM_CONSTANT_String",	JVM_CONSTANT_String);
	print_def("JVM_CONSTANT_Fieldref",	JVM_CONSTANT_Fieldref);
	print_def("JVM_CONSTANT_Methodref",	JVM_CONSTANT_Methodref);
	print_def("JVM_CONSTANT_InterfaceMethodref", JVM_CONSTANT_InterfaceMethodref);
	print_def("JVM_CONSTANT_NameAndType",	JVM_CONSTANT_NameAndType);
	nl();
	print_def("JVM_CONSTANT_UnresolvedClass",	JVM_CONSTANT_UnresolvedClass);
	print_def("JVM_CONSTANT_ClassIndex",		JVM_CONSTANT_ClassIndex);
	print_def("JVM_CONSTANT_UnresolvedString",	JVM_CONSTANT_UnresolvedString);
	print_def("JVM_CONSTANT_StringIndex",		JVM_CONSTANT_StringIndex);
	print_def("JVM_CONSTANT_UnresolvedClassInError",JVM_CONSTANT_UnresolvedClassInError);
	nl();
	print_def("JVM_ACC_PUBLIC",	JVM_ACC_PUBLIC);
	print_def("JVM_ACC_PRIVATE",	JVM_ACC_PRIVATE);
	print_def("JVM_ACC_PROTECTED",	JVM_ACC_PROTECTED);
	print_def("JVM_ACC_STATIC",	JVM_ACC_STATIC);
	print_def("JVM_ACC_FINAL",	JVM_ACC_FINAL);
	print_def("JVM_ACC_SYNCHRONIZED",	JVM_ACC_SYNCHRONIZED);
	print_def("JVM_ACC_SUPER",	JVM_ACC_SUPER);
	print_def("JVM_ACC_VOLATILE",	JVM_ACC_VOLATILE);
	print_def("JVM_ACC_BRIDGE",	JVM_ACC_BRIDGE);
	print_def("JVM_ACC_TRANSIENT",	JVM_ACC_TRANSIENT);
	print_def("JVM_ACC_VARARGS",	JVM_ACC_VARARGS);
	print_def("JVM_ACC_NATIVE",	JVM_ACC_NATIVE);
	print_def("JVM_ACC_INTERFACE",	JVM_ACC_INTERFACE);
	print_def("JVM_ACC_ABSTRACT",	JVM_ACC_ABSTRACT);
	print_def("JVM_ACC_STRICT",	JVM_ACC_STRICT);
	print_def("JVM_ACC_SYNTHETIC",	JVM_ACC_SYNTHETIC);
	print_def("JVM_ACC_ANNOTATION",	JVM_ACC_ANNOTATION);
	print_def("JVM_ACC_ENUM",	JVM_ACC_ENUM);
	print_def("JVM_ACC_HAS_FINALIZER", JVM_ACC_HAS_FINALIZER);
	nl();
	print_def("T_BOOLEAN",	T_BOOLEAN);
	print_def("T_CHAR",	T_CHAR);
	print_def("T_FLOAT",	T_FLOAT);
	print_def("T_DOUBLE",	T_DOUBLE);
	print_def("T_BYTE",	T_BYTE);
	print_def("T_SHORT",	T_SHORT);
	print_def("T_INT",	T_INT);
	print_def("T_LONG",	T_LONG);
	print_def("T_OBJECT",	T_OBJECT);
	print_def("T_ARRAY",	T_ARRAY);
	print_def("T_VOID",	T_VOID);
	nl();
	print_def("tos_btos",	btos);
	print_def("tos_ctos",	ctos);
	print_def("tos_stos",	stos);
	print_def("tos_itos",	itos);
	print_def("tos_ltos",	ltos);
	print_def("tos_ftos",	ftos);
	print_def("tos_dtos",	dtos);
	print_def("tos_atos",	atos);
	nl();
	print_def("_thread_uninitialized",	_thread_uninitialized);
	print_def("_thread_new",		_thread_new);
	print_def("_thread_new_trans",		_thread_new_trans);
	print_def("_thread_in_native",		_thread_in_native);
	print_def("_thread_in_native_trans",	_thread_in_native_trans);
	print_def("_thread_in_vm",		_thread_in_vm);
	print_def("_thread_in_vm_trans",	_thread_in_vm_trans);
	print_def("_thread_in_Java",		_thread_in_Java);
	print_def("_thread_in_Java_trans",	_thread_in_Java_trans);
	print_def("_thread_blocked",		_thread_blocked);
	print_def("_thread_blocked_trans",	_thread_blocked_trans);
	print_def("_thread_max_state",		_thread_max_state);
	nl();
	print_def("class_unparsable_by_gc",	instanceKlass::unparsable_by_gc);
	print_def("class_allocated",		instanceKlass::allocated);
	print_def("class_loaded",		instanceKlass::loaded);
	print_def("class_linked",		instanceKlass::linked);
	print_def("class_being_initialized",	instanceKlass::being_initialized);
	print_def("class_fully_initialized",	instanceKlass::fully_initialized);
	print_def("class_init_error",		instanceKlass::initialization_error);
	nl();
	print_def("flag_methodInterface",	1 << ConstantPoolCacheEntry::methodInterface);
	print_def("flag_volatileField",		1 << ConstantPoolCacheEntry::volatileField);
	print_def("flag_vfinalMethod",		1 << ConstantPoolCacheEntry::vfinalMethod);
	print_def("flag_finalField",		1 << ConstantPoolCacheEntry::finalField);
	nl();
	print_def("INVOCATIONCOUNTER_COUNTINCREMENT", InvocationCounter::count_increment);
	nl();
	VMStructs::print_vm_offsets();
	nl();
	print_def("VMSYMBOLS_ArithmeticException", vmSymbols::java_lang_ArithmeticException_enum);
	print_def("VMSYMBOLS_ArrayIndexOutOfBounds", vmSymbols::java_lang_ArrayIndexOutOfBoundsException_enum);
	print_def("VMSYMBOLS_ArrayStoreException", vmSymbols::java_lang_ArrayStoreException_enum);
	print_def("VMSYMBOLS_ClassCastException", vmSymbols::java_lang_ClassCastException_enum);
	print_def("VMSYMBOLS_NullPointerException", vmSymbols::java_lang_NullPointerException_enum);
	print_def("VMSYMBOLS_AbstractMethodError", vmSymbols::java_lang_AbstractMethodError_enum);
	print_def("VMSYMBOLS_IncompatibleClassChangeError", vmSymbols::java_lang_IncompatibleClassChangeError_enum);
	print_def("VMSYMBOLS_InternalError", vmSymbols::java_lang_InternalError_enum);

	return 0;
}

#endif // STATIC_OFFSETS
