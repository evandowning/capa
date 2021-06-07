# Copyright (C) 2020 FireEye, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import binaryninja

import capa.features.extractors.binja.helpers
from capa.features import Characteristic
from capa.features.extractors import loops


def extract_function_calls_to(f):
    """extract callers to a function

    args:
        f (binja func_t)
    """
    for caller_addr in f.callers:
        yield Characteristic("calls to"), caller_addr


def extract_function_loop(f):
    """extract loop indicators from a function

    args:
        f (binja func_t)
    """
    edges = []

    # construct control flow graph
    for bb in f.basic_blocks:
        for edge in bb.outgoing_edges:
            edges.append((bb.start, edge.target.start))

    if loops.has_loop(edges):
        yield Characteristic("loop"), f.start


def extract_recursive_call(f):
    """extract recursive function call

    args:
        f (binja func_t)
    """
    if capa.features.extractors.binja.helpers.is_function_recursive(f):
        yield Characteristic("recursive call"), f.start


def extract_features(f):
    """extract function features

    arg:
        f (binja func_t)
    """
    for func_handler in FUNCTION_HANDLERS:
        for (feature, ea) in func_handler(f):
            yield feature, ea


FUNCTION_HANDLERS = (extract_function_calls_to, extract_function_loop, extract_recursive_call)


def main():
    """ """
    features = []
    for f in capa.features.extractors.binja.get_functions(skip_libs=True):
        features.extend(list(extract_features(f)))

    import pprint

    pprint.pprint(features)


if __name__ == "__main__":
    main()
