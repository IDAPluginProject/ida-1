import struct, copy
import idc, idautils, ida_name, ida_bytes, ida_ua, ida_search, ida_segment
from consts import constant_arrays, constant_values

if 'g_fc_prefix_cmt' not in globals():
    g_fc_prefix_cmt = 'FC: '
if 'g_fc_prefix_var' not in globals():
    g_fc_prefix_var = 'FC_'
    
# Limit max scan size to avoid memory issues (e.g. 64MB)
MAX_SCAN_SIZE = 64 * 1024 * 1024

def get_bitness(seg_start):
    s = ida_segment.getseg(seg_start)
    if not s:
        return 1, 4, 0xFFFFFFFF, '0x{:08X}' # Default 32-bit
    
    if s.bitness == 1:
        return 1, 4, 0xFFFFFFFF, '0x{:08X}'
    elif s.bitness == 2:
        return 2, 8, 0xFFFFFFFFFFFFFFFF, '0x{:016X}'
    return 1, 4, 0xFFFFFFFF, '0x{:08X}'

# Existing helper (kept for structure compatibility)
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

# Optimized helper
def convert_to_bytes(const, big_endian=False):
    return bytes(convert_to_byte_array(const, big_endian))

def main():
    print("[*] Loading cryptographic constants.")
    constant_arrays2 = []
    # Preserve order for priority
    for i, const in enumerate(constant_arrays):
        const["byte_array"] = convert_to_byte_array(const)
        const["search_bytes"] = bytes(const["byte_array"])
        const["original_idx"] = i * 2 
        constant_arrays2.append(const)
        
        if const["size"] != "B":
            const = copy.copy(const)
            const["byte_array"] = convert_to_byte_array(const, big_endian=True)
            const["search_bytes"] = bytes(const["byte_array"])
            const["original_idx"] = i * 2 + 1
            constant_arrays2.append(const)

    # Precompute constant values map for O(1) lookup
    const_val_map = {}
    for const in constant_values:
        const_val_map[const["value"]] = const

    for seg_start in idautils.Segments():
        # Setup segment specific info
        bitness_code, value_len, bad_addr, address_format = get_bitness(seg_start)
        
        seg_name = idc.get_segm_name(seg_start)
        seg_end = idc.get_segm_end(seg_start)
        seg_size = seg_end - seg_start
        is_code = (idc.get_segm_attr(seg_start, idc.SEGATTR_TYPE) == idc.SEG_CODE)
        
        print("[*] Scanning segment {} for cryptographic constants.".format(seg_name))
        
        scan_size = min(seg_size, MAX_SCAN_SIZE)
        if seg_size > MAX_SCAN_SIZE:
             print("[!] Segment size {} exceeds limit {}. Only first {} bytes will be scanned.".format(seg_size, MAX_SCAN_SIZE, MAX_SCAN_SIZE))

        try:
            seg_data = ida_bytes.get_bytes(seg_start, scan_size)
        except:
            seg_data = None
            
        if not seg_data:
            print("[!] Failed to read segment data for {}. Skipping.".format(seg_name))
            continue

        # ---------------------------------------------------------
        # 1. Dense Constant Array Search
        # ---------------------------------------------------------
        all_matches = [] # List of (ea, priority, const)

        for const in constant_arrays2:
            pattern = const["search_bytes"]
            if len(pattern) > len(seg_data):
                continue
                
            start_index = 0
            while True:
                try:
                    idx = seg_data.find(pattern, start_index)
                except:
                    break 
                if idx == -1:
                    break
                
                ea = seg_start + idx
                all_matches.append((ea, const["original_idx"], const))
                start_index = idx + 1

        # Sort matches by address, then by priority (original index)
        all_matches.sort(key=lambda x: (x[0], x[1]))

        processed_until = 0
        for ea, _, const in all_matches:
            if ea < processed_until:
                continue

            print(("[*] " + address_format + ": Found const array {}.{}").format(ea, const["algorithm"], const["name"]))
            idc.set_name(ea, g_fc_prefix_var + const["name"], ida_name.SN_FORCE)
            
            try:
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
            except:
                pass

            processed_until = ea + len(const["byte_array"])

        if is_code:
            # ---------------------------------------------------------
            # 2. Sparse Constant Search (Code segments only)
            # ---------------------------------------------------------
            sparse_matches = [] # (ea, priority, const, end_addr)
            
            for const in constant_arrays2:
                if len(const["search_bytes"]) < value_len:
                    continue
                    
                first_chunk = const["search_bytes"][:value_len]
                start_index = 0
                
                while True:
                    idx = seg_data.find(first_chunk, start_index)
                    if idx == -1:
                        break
                    
                    ea = seg_start + idx
                    tmp = ea + value_len
                    
                    # Check sparse pattern
                    found_full = True
                    for j in range(1, len(const["byte_array"])//value_len):
                        val_bytes = const["search_bytes"][value_len*j : value_len*j+value_len]
                        val = int.from_bytes(val_bytes, byteorder='little')
                        
                        match_j = False
                        current_buf_off = tmp - seg_start
                        
                        # Look ahead range 1 to 10
                        found_offset = -1
                        for i in range(1, 10):
                            check_off = current_buf_off + i
                            if check_off + value_len > len(seg_data):
                                break
                            
                            try:
                                v_bytes = seg_data[check_off : check_off + value_len]
                                v = int.from_bytes(v_bytes, byteorder='little')
                                
                                if v == val:
                                    tmp = tmp + i + value_len
                                    match_j = True
                                    break
                            except:
                                break
                                
                        if not match_j:
                            found_full = False
                            break
                            
                    if found_full:
                        sparse_matches.append((ea, const["original_idx"], const, tmp))
                    
                    start_index = idx + 1

            sparse_matches.sort(key=lambda x: (x[0], x[1]))
            
            processed_until = 0
            for ea, _, const, end_addr in sparse_matches:
                if ea < processed_until:
                    continue
                    
                print(("[*] " + address_format + ": Found sparse constant {}.{}").format(ea, const["algorithm"], const["name"]))
                
                prev_head = idc.prev_head(ea)
                cmt = idc.get_cmt(prev_head, 0)
                if cmt and cmt != g_fc_prefix_cmt + const["name"]:
                     if g_fc_prefix_cmt + const["name"] not in cmt:
                        idc.set_cmt(prev_head, cmt + '\n' + g_fc_prefix_cmt + const["name"], 0)
                else:
                    idc.set_cmt(prev_head, g_fc_prefix_cmt + const["name"], 0)
                
                processed_until = end_addr

            # ---------------------------------------------------------
            # 3. Immediate Operand Search (unchanged logic, no need for seg_data)
            # ---------------------------------------------------------
            funcs = idautils.Functions(seg_start, seg_end)
            for f in funcs:
                flags = idc.get_func_flags(f)
                if (not flags & (idc.FUNC_LIB | idc.FUNC_THUNK)):
                    ea = f
                    f_end = idc.get_func_attr(f, idc.FUNCATTR_END)
                    
                    while (ea < f_end) and (ea != idc.BADADDR):
                        insn = ida_ua.insn_t()
                        if not ida_ua.decode_insn(insn, ea):
                            ea = idc.next_head(ea, f_end)
                            continue
                            
                        # Check operands
                        found_imm = False
                        for i in range(len(insn.ops)):
                            if insn.ops[i].type == ida_ua.o_void:
                                break
                            if insn.ops[i].type == ida_ua.o_imm:
                                val = insn.ops[i].value
                                
                                # O(1) Lookup
                                if val in const_val_map:
                                    const = const_val_map[val]
                                    print(("[*] " + address_format + ": Found immediate operand constant {}.{}").format(ea, const["algorithm"], const["name"]))
                                    cmt = idc.get_cmt(ea, 0)
                                    if cmt:
                                        if g_fc_prefix_cmt + const["name"] not in cmt:
                                            idc.set_cmt(ea, cmt + ' ' + g_fc_prefix_cmt + const["name"], 0)
                                    else:
                                        idc.set_cmt(ea, g_fc_prefix_cmt + const["name"], 0)
                                    found_imm = True
                                    break
                        
                        if found_imm:
                             pass
                             
                        ea = idc.next_head(ea, f_end)
                    
                    
    print("[*] Analysis completed.")

if __name__ == '__main__':
    main()
