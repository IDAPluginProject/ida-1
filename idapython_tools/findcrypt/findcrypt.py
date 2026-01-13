import struct, copy
import idc, idautils, ida_name, ida_bytes, ida_ua, ida_search
from consts import constant_arrays, constant_values

if 'g_fc_prefix_cmt' not in globals():
    g_fc_prefix_cmt = 'FC: '
if 'g_fc_prefix_var' not in globals():
    g_fc_prefix_var = 'FC_'

s = ida_segment.getseg(idc.here())
if s.bitness == 1:
    bad_addr = 0xFFFFFFFF
    address_format = '0x{:08X}'
    get_value = ida_bytes.get_dword
    value_len = 4
elif s.bitness == 2:
    bad_addr = 0xFFFFFFFFFFFFFFFF
    address_format = '0x{:016X}'
    get_value = ida_bytes.get_qword
    value_len = 8

def convert_to_byte_array(const, big_endian=False):
    byte_array = []
    if const["size"] == "B":
        byte_array = const["array"]
    elif const["size"] == "L":
        for val in const["array"]:
            if big_endian:
                byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack(">L", val)))
            else:
                byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack("<L", val)))
    elif const["size"] == "Q":
        for val in const["array"]:
            if big_endian:
                byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack(">Q", val)))
            else:
                byte_array += list(map(lambda x:x if type(x) == int else ord(x), struct.pack("<Q", val)))
    return byte_array

def main():
    print("[*] Loading crypto constants")
    constant_arrays2 = []
    for const in constant_arrays:
        const["byte_array"] = convert_to_byte_array(const)
        constant_arrays2.append(const)
        if const["size"] != "B":
            const = copy.copy(const)
            const["byte_array"] = convert_to_byte_array(const, big_endian=True)
            constant_arrays2.append(const)

    for seg_start in idautils.Segments():
        print("[*] Searching for crypto constants in {}".format(idc.get_segm_name(seg_start)))
        ea = seg_start
        seg_end = idc.get_segm_end(seg_start)
        while ea < seg_end:
            bbbb = list(struct.unpack("BBBB", idc.get_bytes(ea, 4)))
            for const in constant_arrays2:
                if bbbb != const["byte_array"][:4]:
                    continue
                if list(map(lambda x:x if type(x) == int else ord(x), idc.get_bytes(ea, len(const["byte_array"])))) == const["byte_array"]:
                    print(("[*] " + address_format + ": Found const array {}.{}").format(ea, const["algorithm"], const["name"]))
                    idc.set_name(ea, g_fc_prefix_var + const["name"], ida_name.SN_FORCE)
                    if const["size"] == "B":
                        ida_bytes.del_items(ea, 0, len(const["array"]))
                        idc.create_byte(ea)
                    elif const["size"] == "L":
                        ida_bytes.del_items(ea, 0, len(const["array"])*4)
                        idc.create_dword(ea)
                    elif const["size"] == "Q":
                        ida_bytes.del_items(ea, 0, len(const["array"])*8)
                        idc.create_qword(ea)
                    idc.make_array(ea, len(const["array"]))
                    ea += len(const["byte_array"]) - 4
                    break
            ea += 4

        ea = seg_start
        if idc.get_segm_attr(ea, idc.SEGATTR_TYPE) == idc.SEG_CODE:
            while ea < seg_end:
                d = ida_bytes.get_dword(ea)
                for const in constant_arrays2:
                    if d != int.from_bytes(const["byte_array"][:value_len], byteorder='little'):
                        continue

                    tmp = ea + value_len
                    for j in range(1, len(const["byte_array"])//value_len):
                        val = int.from_bytes(const["byte_array"][value_len*j:value_len*j+value_len], byteorder='little')
                        for i in range(1, 10):
                            if ida_bytes.get_dword(tmp + i) == val:
                                tmp = tmp + i + 4
                                break
                        else:
                            break
                    else:
                        print(("[*] " + address_format + ": Found sparse constant {}.{}").format(ea, const["algorithm"], const["name"]))
                        cmt = idc.get_cmt(idc.prev_head(ea), 0)
                        if cmt and cmt != g_fc_prefix_cmt + const["name"]:
                            idc.set_cmt(idc.prev_head(ea), cmt + '\n' + g_fc_prefix_cmt + const["name"], 0)
                        else:
                            idc.set_cmt(idc.prev_head(ea), g_fc_prefix_cmt + const["name"], 0)
                        ea = tmp
                        break
                ea += 1

    print("[*] Searching for crypto constants in immediate operand")
    funcs = idautils.Functions()
    for f in funcs:
        flags = idc.get_func_flags(f)
        if (not flags & (idc.FUNC_LIB | idc.FUNC_THUNK)):
            ea = f
            f_end = idc.get_func_attr(f, idc.FUNCATTR_END)
            while (ea < f_end):
                imm_operands = []
                insn = ida_ua.insn_t()
                ida_ua.decode_insn(insn, ea)
                for i in range(len(insn.ops)):
                    if insn.ops[i].type == ida_ua.o_void:
                        break
                    if insn.ops[i].type == ida_ua.o_imm:
                        imm_operands.append(insn.ops[i].value)
                if len(imm_operands) == 0:
                    ea = idc.find_code(ea, ida_search.SEARCH_DOWN)
                    continue
                for const in constant_values:
                    if const["value"] in imm_operands:
                        print(("[*] " + address_format + ": Found immediate operand constant {}.{}").format(ea, const["algorithm"], const["name"]))
                        cmt = idc.get_cmt(ea, 0)
                        if cmt:
                            idc.set_cmt(ea, cmt + ' ' + g_fc_prefix_cmt + const["name"], 0)
                        else:
                            idc.set_cmt(ea, g_fc_prefix_cmt + const["name"], 0)
                        break
                ea = idc.find_code(ea, ida_search.SEARCH_DOWN)
    print("[*] Finished")

if __name__ == '__main__':
    main()
