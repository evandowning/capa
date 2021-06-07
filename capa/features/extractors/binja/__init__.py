# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import binaryninja

import capa.features.extractors.binja.file
import capa.features.extractors.binja.insn
import capa.features.extractors.binja.function
import capa.features.extractors.binja.basicblock
from capa.features.extractors import FeatureExtractor


class FunctionHandle:
    def __init__(self, inner):
        self._inner = inner

    def __int__(self):
        return self.start

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __iter__(self):
        return iter(self._inner)


class BasicBlockHandle:
    """this acts like an idaapi.BasicBlock but with __int__()"""

    def __init__(self, inner):
        self._inner = inner

    def __int__(self):
        return self.start

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __iter__(self):
        return iter(self._inner)

class InstructionHandle:
    """this acts like an idaapi.insn_t but with __int__()"""

    def __init__(self, tokens, start, byte_length):
        self.tokens = tokens
        self.start = start
        self.byte_length = byte_length

    def __int__(self):
        return self.start


class BinjaFeatureExtractor(FeatureExtractor):
    def __init__(self, bv, path):
        super(BinjaFeatureExtractor, self).__init__()
        self.bv = bv
        self.path = path

    def get_base_address(self):
        return self.bv.start

    def extract_file_features(self):
        for (feature, ea) in capa.features.extractors.binja.file.extract_features(self.bv):
            yield feature, ea

    def get_functions(self):
        import capa.features.extractors.binja.helpers as binja_helpers

        # data structure shared across functions yielded here.
        # useful for caching analysis relevant across a single workspace.
        ctx = {}

        # only retrieve internal functions as defined by BinaryNinja
        for f in binja_helpers.get_functions(self.bv, skip_libs=True):
            setattr(f, "ctx", ctx)
            yield FunctionHandle(f)

    #TODO
    @staticmethod
    def get_function(ea):
        f = idaapi.get_func(ea)
        setattr(f, "ctx", {})
        return FunctionHandle(f)

    def extract_function_features(self, f):
        for (feature, ea) in capa.features.extractors.binja.function.extract_features(f):
            yield feature, ea

    def get_basic_blocks(self, f):
        import capa.features.extractors.binja.helpers as binja_helpers

        for bb in binja_helpers.get_function_blocks(f):
            yield BasicBlockHandle(bb)

    def extract_basic_block_features(self, f, bb):
        for (feature, ea) in capa.features.extractors.binja.basicblock.extract_features(self.bv, f, bb):
            yield feature, ea

    def get_instructions(self, f, bb):
        import capa.features.extractors.binja.helpers as binja_helpers

        for tokens,start,byte_length in binja_helpers.get_instructions_from_bb(bb):
            yield InstructionHandle(tokens,start,byte_length)

    def extract_insn_features(self, f, bb, insn):
        for (feature, ea) in capa.features.extractors.binja.insn.extract_features(self.bv, f, bb, insn):
            yield feature, ea
