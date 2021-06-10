# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import struct

import binaryninja

import capa.features.extractors.helpers
import capa.features.extractors.strings
import capa.features.extractors.binja.helpers
from capa.features import String, Characteristic
from capa.features.file import Export, Import, Section, FunctionName


def check_segment_for_pe(seg):
    """check segment for embedded PE

    adapted for IDA from:
    https://github.com/vivisect/vivisect/blob/7be4037b1cecc4551b397f840405a1fc606f9b53/PE/carve.py#L19

    args:
        seg (IDA segment_t)
    """
    seg_max = seg.end_ea
    mz_xor = [
        (
            capa.features.extractors.helpers.xor_static(b"MZ", i),
            capa.features.extractors.helpers.xor_static(b"PE", i),
            i,
        )
        for i in range(256)
    ]

    todo = []
    for (mzx, pex, i) in mz_xor:
        for off in capa.features.extractors.ida.helpers.find_byte_sequence(seg.start_ea, seg.end_ea, mzx):
            todo.append((off, mzx, pex, i))

    while len(todo):
        off, mzx, pex, i = todo.pop()

        # The MZ header has one field we will check e_lfanew is at 0x3c
        e_lfanew = off + 0x3C

        if seg_max < (e_lfanew + 4):
            continue

        newoff = struct.unpack("<I", capa.features.extractors.helpers.xor_static(idc.get_bytes(e_lfanew, 4), i))[0]

        peoff = off + newoff
        if seg_max < (peoff + 2):
            continue

        if idc.get_bytes(peoff, 2) == pex:
            yield (off, i)

        for nextres in capa.features.extractors.ida.helpers.find_byte_sequence(off + 1, seg.end_ea, mzx):
            todo.append((nextres, mzx, pex, i))


#TODO
def extract_file_embedded_pe(bv):
    """extract embedded PE features

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for name,s in capa.features.extractors.binja.helpers.get_segments(bv,skip_header_segments=True):
        for (ea, _) in check_segment_for_pe(seg):
            yield Characteristic("embedded pe"), ea


#TODO
def extract_file_export_names(bv):
    """extract function exports"""
    for func in bv.functions:
        if func.symbol is not None:
            f_type_name = func.symbol.type.name
            if f_type_name == '':
                addr = func.start
                name = func.name
                yield Export(name), ea


def extract_file_import_names(bv):
    """extract function imports
    1. imports by ordinal:
     - modulename.#ordinal
    2. imports by name, results in two features to support importname-only
       matching:
     - modulename.importname
     - importname
    """
    for (ea, info) in capa.features.extractors.binja.helpers.get_file_imports(bv).items():
        if info[1] and info[2]:
            # e.g. in mimikatz: ('cabinet', 'FCIAddFile', 11L)
            # extract by name here and by ordinal below
            for name in capa.features.extractors.helpers.generate_symbols(info[0], info[1]):
                yield Import(name), ea
            dll = info[0]
            symbol = "#%d" % (info[2])
        elif info[1]:
            dll = info[0]
            symbol = info[1]
        elif info[2]:
            dll = info[0]
            symbol = "#%d" % (info[2])
        else:
            continue

        for name in capa.features.extractors.helpers.generate_symbols(dll, symbol):
            yield Import(name), ea

def extract_file_section_names(bv):
    """extract section names

    IDA must load resource sections for this to be complete
        - '-R' from console
        - Check 'Load resource sections' when opening binary in IDA manually
    """
    for name,s in capa.features.extractors.binja.helpers.get_segments(bv,skip_header_segments=True):
        yield Section(name), s.start


def extract_file_strings(bv):
    """extract strings"""

    start_addr = bv.start
    end_addr = bv.end
    offset = 0

    while start_addr+offset < end_addr:
        try:
            bnString = bv.get_string_at(start_addr+offset)
            if bnString is None:
                offset += 1
                continue
            string = bnString.value

            yield String(String), (start_addr+offset)

            if bnString.length == 0:
                offset += 1
            else:
                offset += bnString.length
        except:
            break

#   """
#   IDA must load resource sections for this to be complete
#       - '-R' from console
#       - Check 'Load resource sections' when opening binary in IDA manually
#   """
#   for seg in capa.features.extractors.ida.helpers.get_segments():
#       seg_buff = capa.features.extractors.ida.helpers.get_segment_buffer(seg)

#       for s in capa.features.extractors.strings.extract_ascii_strings(seg_buff):
#           yield String(s.s), (seg.start_ea + s.offset)

#       for s in capa.features.extractors.strings.extract_unicode_strings(seg_buff):
#           yield String(s.s), (seg.start_ea + s.offset)


def extract_file_function_names(bv):
    """
    extract the names of statically-linked library functions.
    """
#   for ea in idautils.Functions():
#       if idaapi.get_func(ea).flags & idaapi.FUNC_LIB:
#           name = idaapi.get_name(ea)
#           yield FunctionName(name), ea

    for s in bv.get_symbols():
        if s.type == binaryninja.enums.SymbolType.LibraryFunctionSymbol:
            yield FunctionName(s.name), s.address


def extract_features(bv):
    """extract file features"""
    for file_handler in FILE_HANDLERS:
        for feature, va in file_handler(bv):
            yield feature, va


FILE_HANDLERS = (
    extract_file_export_names,
    extract_file_import_names,
    extract_file_strings,
    extract_file_section_names,
#   extract_file_embedded_pe,
    extract_file_function_names,
)


def main():
    """ """
    import pprint

    pprint.pprint(list(extract_features()))


if __name__ == "__main__":
    main()
