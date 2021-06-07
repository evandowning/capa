# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import string

import binaryninja


def find_byte_sequence(start, end, seq):
    """yield all ea of a given byte sequence

    args:
        start: min virtual address
        end: max virtual address
        seq: bytes to search e.g. b"\x01\x03"
    """
    seq = " ".join(["%02x" % b for b in seq])
    while True:
        ea = idaapi.find_binary(start, end, seq, 0, idaapi.SEARCH_DOWN)
        if ea == idaapi.BADADDR:
            break
        start = ea + 1
        yield ea


def get_functions(bv, start=None, end=None, skip_libs=False):
    """get functions, range optional

    args:
        start: min virtual address
        end: max virtual address

    ret:
        yield func_t*
    """
    if start is None:
        functions = bv.functions
    else:
        functions = bv.get_functions_at(start)

    for func in functions:
        if skip_libs is True:
            if func.symbol is not None:
                f_type_name = func.symbol.type.name
                if f_type_name == 'FunctionSymbol':
                    yield func
        else:
            yield func


def get_segments(bv,skip_header_segments=False):
    """get list of segments (sections) in the binary image

    args:
        skip_header_segments: IDA may load header segments - skip if set
    """
    for name,s in bv.sections.items():
        yield name,s


def get_segment_buffer(seg):
    """return bytes stored in a given segment

    decrease buffer size until IDA is able to read bytes from the segment
    """
    buff = b""
    sz = seg.end_ea - seg.start_ea

    while sz > 0:
        buff = idaapi.get_bytes(seg.start_ea, sz)
        if buff:
            break
        sz -= 0x1000

    # IDA returns None if get_bytes fails, so convert for consistent return type
    return buff if buff else b""


def get_file_imports(bv):
    """get file imports"""
    imports = {}

#   for idx in range(idaapi.get_import_module_qty()):
#       library = idaapi.get_import_module_name(idx)

#       if not library:
#           continue

#       def inspect_import(ea, function, ordinal):
#           if function and function.startswith("__imp_"):
#               # handle mangled names starting
#               function = function[len("__imp_") :]
#           imports[ea] = (library.lower(), function, ordinal)
#           return True

#       idaapi.enum_import_names(idx, inspect_import)

    for s in bv.get_symbols():
        if s.type == binaryninja.enums.SymbolType.ImportAddressSymbol:
            imports[s.address] = (s.namespace.name[0].lower(),s.name,s.ordinal)

    return imports


def get_instructions_in_range(start, end):
    """yield instructions in range

    args:
        start: virtual address (inclusive)
        end: virtual address (exclusive)
    yield:
        (insn_t*)
    """
    for head in idautils.Heads(start, end):
        insn = idautils.DecodeInstruction(head)
        if insn:
            yield insn

def get_instructions_from_bb(bb):
    start = bb.start
    for insn in bb:
        tokens = insn[0]
        byte_length = insn[1]
        yield tokens,start,byte_length
        start += byte_length

def is_operand_equal(op1, op2):
    """compare two IDA op_t"""
    if op1.flags != op2.flags:
        return False

    if op1.dtype != op2.dtype:
        return False

    if op1.type != op2.type:
        return False

    if op1.reg != op2.reg:
        return False

    if op1.phrase != op2.phrase:
        return False

    if op1.value != op2.value:
        return False

    if op1.addr != op2.addr:
        return False

    return True


def is_basic_block_equal(bb1, bb2):
    """compare two IDA BasicBlock"""
    if bb1.start_ea != bb2.start_ea:
        return False

    if bb1.end_ea != bb2.end_ea:
        return False

    if bb1.type != bb2.type:
        return False

    return True


def basic_block_size(bb):
    """calculate size of basic block"""
    return bb.end_ea - bb.start_ea


def read_bytes_at(ea, count):
    """ """
    # check if byte has a value, see get_wide_byte doc
    if not idc.is_loaded(ea):
        return b""

    segm_end = idc.get_segm_end(ea)
    if ea + count > segm_end:
        return idc.get_bytes(ea, segm_end - ea)
    else:
        return idc.get_bytes(ea, count)


# NOTE: not necessary because of extract_insn_string_features() in insn.py
def find_string_at(bv, ea, min=4):
    """check if ASCII string exists at a given virtual address"""
    found = idaapi.get_strlit_contents(ea, -1, idaapi.STRTYPE_C)
    if found and len(found) > min:
        try:
            found = found.decode("ascii")
            # hacky check for IDA bug; get_strlit_contents also reads Unicode as
            # myy__uunniiccoodde when searching in ASCII mode so we check for that here
            # and return the fixed up value
            if len(found) >= 3 and found[1::2] == found[2::2]:
                found = found[0] + found[1::2]
            return found
        except UnicodeDecodeError:
            pass
    return ""


def get_op_phrase_info(op):
    """parse phrase features from operand

    Pretty much dup of sark's implementation:
        https://github.com/tmr232/Sark/blob/master/sark/code/instruction.py#L28-L73
    """
    if op.type not in (idaapi.o_phrase, idaapi.o_displ):
        return {}

    scale = 1 << ((op.specflag2 & 0xC0) >> 6)
    offset = op.addr

    if op.specflag1 == 0:
        index = None
        base = op.reg
    elif op.specflag1 == 1:
        index = (op.specflag2 & 0x38) >> 3
        base = (op.specflag2 & 0x07) >> 0

        if op.reg == 0xC:
            if base & 4:
                base += 8
            if index & 4:
                index += 8
    else:
        return {}

    if (index == base == idautils.procregs.sp.reg) and (scale == 1):
        # HACK: This is a really ugly hack. For some reason, phrases of the form `[esp + ...]` (`sp`, `rsp` as well)
        # set both the `index` and the `base` to `esp`. This is not significant, as `esp` cannot be used as an
        # index, but it does cause issues with the parsing.
        # This is only relevant to Intel architectures.
        index = None

    return {"base": base, "index": index, "scale": scale, "offset": offset}


def is_op_write(insn, op):
    """Check if an operand is written to (destination operand)"""
    return idaapi.has_cf_chg(insn.get_canon_feature(), op.n)


def is_op_read(insn, op):
    """Check if an operand is read from (source operand)"""
    return idaapi.has_cf_use(insn.get_canon_feature(), op.n)


def is_op_offset(insn, op):
    """Check is an operand has been marked as an offset (by auto-analysis or manually)"""
    flags = idaapi.get_flags(insn.ea)
    return ida_bytes.is_off(flags, op.n)


def is_sp_modified(insn):
    """determine if instruction modifies SP, ESP, RSP"""
#   for op in get_insn_ops(insn, target_ops=(idaapi.o_reg,)):
#       if op.reg == idautils.procregs.sp.reg and is_op_write(insn, op):
#           # register is stack and written
#           return True
#   return False

    for i in insn.tokens:
        if i.type == binaryninja.enums.InstructionTextTokenType['RegisterToken']:
            if i.text in ['sp','esp','rsp']:
                return
    return False


def is_bp_modified(insn):
    """check if instruction modifies BP, EBP, RBP"""
#   for op in get_insn_ops(insn, target_ops=(idaapi.o_reg,)):
#       if op.reg == idautils.procregs.bp.reg and is_op_write(insn, op):
#           # register is base and written
#           return True
#   return False

    for i in insn.tokens:
        if i.type == binaryninja.enums.InstructionTextTokenType['RegisterToken']:
            if i.text in ['bp','ebp','rbp']:
                return
    return False


def is_frame_register(reg):
    """check if register is sp or bp"""
    return reg in (idautils.procregs.sp.reg, idautils.procregs.bp.reg)


#   def get_insn_ops(insn, target_ops=()):
#       """yield op_t for instruction, filter on type if specified"""
#       for op in insn.ops:
#           if op.type == idaapi.o_void:
#               # avoid looping all 6 ops if only subset exists
#               break
#           if target_ops and op.type not in target_ops:
#               continue
#           yield op


def is_op_stack_var(ea, index):
    """check if operand is a stack variable"""
    return idaapi.is_stkvar(idaapi.get_flags(ea), index)


def mask_op_val(op):
    """mask value by data type

    necessary due to a bug in AMD64

    Example:
        .rsrc:0054C12C mov [ebp+var_4], 0FFFFFFFFh

        insn.Op2.dtype == idaapi.dt_dword
        insn.Op2.value == 0xffffffffffffffff
    """
    masks = {
        idaapi.dt_byte: 0xFF,
        idaapi.dt_word: 0xFFFF,
        idaapi.dt_dword: 0xFFFFFFFF,
        idaapi.dt_qword: 0xFFFFFFFFFFFFFFFF,
    }
    return masks.get(op.dtype, op.value) & op.value


def is_function_recursive(f):
    """check if function is recursive

    args:
        f (binja func_t)
    """
    for caller_addr in f.callers:
        if caller_addr == f.start:
            return True
    return False


def is_basic_block_tight_loop(bb):
    """check basic block loops to self

    true if last instruction in basic block branches to basic block start

    args:
        f (binja func_t)
        bb (binja BasicBlock)
    """
    for edge in bb.outgoing_edges:
        if edge.target.start == bb.start:
            return True
    return False


def find_data_reference_from_insn(bv, insn, max_depth=10):
    """search for data reference from instruction, return address of instruction if no reference exists"""
    depth = 0
    ea = insn.start

    while True:
        data_refs = bv.get_data_refs(ea)

        if len(data_refs) != 1:
            # break if no refs or more than one ref (assume nested pointers only have one data reference)
            break

        if ea == data_refs[0]:
            # break if circular reference
            break

#       if not idaapi.is_mapped(data_refs[0]):
#           # break if address is not mapped
#           break

        depth += 1
        if depth > max_depth:
            # break if max depth
            break

        ea = data_refs[0]

    return ea


def get_function_blocks(f):
    """yield basic blocks contained in specified function

    args:
        f (binja func_t)
    yield:
        block (binja BasicBlock)
    """
    for bb in f:
        yield bb


def is_basic_block_return(bb):
    """check if basic block is return block"""
    return bb.type == idaapi.fcb_ret
