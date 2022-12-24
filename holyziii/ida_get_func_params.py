import idc
import idaapi
import ida_funcs

def check_func_prolog(ea):
    return idc.print_insn_mnem(ea) == "push" and idc.print_operand(ea, 0) == "rbp"\
        and  idc.print_insn_mnem(ea + 1) == "mov" and idc.print_operand(ea + 1, 0) == "rbp" and idc.print_operand(ea + 1, 1) == "rsp"

def get_function_addresses():
    start = 0x0000820
    end = 0x340F

    functions = []
    i = start
    while i < end:
        if check_func_prolog(i):
            functions.append(i)
            i += 8
        else:
            i += 1 

    assert len(functions) == 256
    return functions

def name_check_functions():
    functions = get_function_addresses()
    for i, fea in enumerate(functions):
        ida_funcs.add_func(fea)
        idc.set_name(fea, f"FUNC_{i}", idaapi.SN_FORCE)

def get_func_params(fea):
    ea = fea
    xorval = -1
    idx = -1
    cmpval = -1
    while ea < fea + 50:
        if idc.print_insn_mnem(ea) == "mov" and idc.print_operand(ea, 0) == "r8b":
            xorval = idc.get_operand_value(ea, 1)
            ea += 3
        elif idc.print_insn_mnem(ea) == "movzx" and idc.print_operand(ea, 0) == "rcx":
            idx = idc.get_operand_value(ea, 1)
            ea += 3
        elif idc.print_insn_mnem(ea) == "cmp" and idc.print_operand(ea, 0) == "r8":
            # cmp     r8, 69h
            cmpval = idc.get_operand_value(ea, 1)
            break
        else:
            ea += 1
    if xorval != -1 and idx != -1 and cmpval != -1:
        return (idx, xorval, cmpval)
    else:
        raise ValueError("Parsing failed")


# name_check_functions()
params = []
for fea in get_function_addresses():
    params.append(get_func_params(fea))

print(params)