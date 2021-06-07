import sys
import binaryninja as binja

# Based on https://github.com/Vector35/binaryninja-api/blob/dev/python/examples/instruction_iterator.py

def _main():
    if len(sys.argv) != 2:
        sys.exit(1)

    fn = sys.argv[1]

    bv = binja.binaryview.BinaryViewType.get_view_of_file(fn)
    bv.update_analysis_and_wait()

    imports = dict()

    # Get imports
    for s in bv.get_symbols():
        if s.type == binja.enums.SymbolType.ImportAddressSymbol:
            imports[s.address] = (hex(s.address),s.namespace,s.name,s.ordinal)

    # Get calls to imports
    # For each Function object
    # https://api.binary.ninja/_modules/binaryninja/function.html#Function
    for func in bv.functions:
#       sys.stdout.write('{0}\n'.format(hex(func.start)))

        # For each BasicBlock object in this function
        # https://api.binary.ninja/_modules/binaryninja/basicblock.html#BasicBlock
        for block in func:
#           sys.stdout.write(' '*2)
#           sys.stdout.write('{0}\n'.format(hex(block.start)))

            insn_start = block.start

            # For each instruction in this function
            # Each is a tuple of InstructionTextToken list and length of bytes decoded
            for insn in block:
                tokens = insn[0]
                byte_length = insn[1]

                if tokens[0].text != 'call':
                    insn_start += byte_length
                    continue

                sys.stdout.write('{0} {1}\n'.format(hex(insn_start),insn))

                for i in tokens:
                    # Get calls to imports
                    typeName = [name for name,value in vars(binja.enums.InstructionTextTokenType).items() if value == i.type][0]
                    if 'AddressToken' in typeName:
                        call_addr = int(i.text,16)
                        if call_addr in imports.keys():
                            print('    ',imports[call_addr])

                insn_start += byte_length

    # Get sections
    for name,s in bv.sections.items():
        print(name,hex(s.start))

    # Get obfuscated strings
    for func in bv.functions:
        for block in func:
            insn_start = block.start
            disas = block.get_disassembly_text()
            if func.start == block.start:
                insn_index = 1
            else:
                insn_index = 0

            for insn in block:
                tokens = insn[0]
                byte_length = insn[1]

                if not tokens[0].text.startswith('mov'):
                    insn_start += byte_length
                    insn_index += 1
                    continue

                sys.stdout.write('{0} {1}\n'.format(hex(insn_start),insn))
                #sys.stdout.write('{0}\n'.format(func.get_low_level_il_at(insn_start)))

                disas_array = [str(d) for d in disas[insn_index].tokens]

                if '}' == disas_array[-1][-1]:
                    try:
                        const = int(disas_array[-2],16)
                        print('character found: ', hex(const), ' ', '"', chr(const), '"')
                    except:
                        pass

                insn_start += byte_length
                insn_index += 1

    # Get strings
    for func in bv.functions:
        for block in func:
            insn_start = block.start
            for insn in block:
                tokens = insn[0]
                byte_length = insn[1]

                for i in tokens:
                    try:
                        ref = int(i.text,16)
                       #ref = 0x404bd5
                       #ref = 0x413ab8

                       #ref = 0x404bd6
                       #ref = 0x413844
                       #ref = 0x404bd7

                        data_refs = bv.get_data_refs(ref)
                        string_refs = bv.get_string_at(ref)
                        print(hex(insn_start),hex(i.address),hex(i.size),tokens,data_refs,string_refs.value)
                    except:
                        pass

                insn_start += byte_length

if __name__ == '__main__':
    _main()
