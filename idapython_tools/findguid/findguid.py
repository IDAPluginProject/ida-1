import idc, ida_idaapi, ida_name, ida_bytes, ida_typeinf
import os, binascii, struct

GUID_LIST_DIR = os.path.join(os.path.dirname(__file__), 'guid_list')
GUID_LIST= []
# [name, prefix, filepath]
GUID_LIST.append(['Class ID', 'CLSID_', os.path.join(GUID_LIST_DIR, 'class.txt')])
GUID_LIST.append(['Interface ID', 'IID_', os.path.join(GUID_LIST_DIR, 'interface.txt')])
GUID_LIST.append(['Folder ID', 'FOLDERID_', os.path.join(GUID_LIST_DIR, 'folder.txt')])
GUID_LIST.append(['Media Type', '', os.path.join(GUID_LIST_DIR, 'media.txt')])

def get_guid_tid():
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(None, 'GUID') or not tif.get_size() == 16:
        print('[*] create GUID struct')
        tif = ida_typeinf.tinfo_t()
        guid_struct_str = """struct GUID {
            unsigned int Data1;
            unsigned short Data2;
            unsigned short Data3;
            unsigned char Data4[8];
        };"""
        ida_typeinf.del_named_type(None, 'GUID', ida_typeinf.NTF_TYPE)
        ida_typeinf.idc_parse_types(guid_struct_str, 0)
        if not tif.get_named_type(None, 'GUID'):
            print('[!] failed to create GUID struct')
            return ida_idaapi.BADADDR
    return tif.force_tid()

def make_binary_pattern(guid):
    # sample guid: 0F87369F-A4E5-4CFC-BD3E-73E6154572DD
    tmp = guid.split('-')
    data = b''
    data += struct.pack('<L', int(tmp[0], 16))
    data += struct.pack('<H', int(tmp[1], 16))
    data += struct.pack('<H', int(tmp[2], 16))
    data += struct.pack('>H', int(tmp[3], 16))
    data += binascii.a2b_hex(tmp[4])

    binary_pattern = ' '.join(map(lambda x:format(x if type(x) == int else ord(x), '02x'), list(data)))
    return binary_pattern

def main():
    tid = get_guid_tid()
    if tid == ida_idaapi.BADADDR:
        print('[!] failed to tid for GUID struct')
        return

    for type_name, type_prefix, filepath in GUID_LIST:
        print('[*] scanning {}'.format(type_name))
        fp = open(filepath, 'r')
        for line in fp.readlines():
            line = line.strip()
            if line == "":
                continue
            guid, guid_name = line.split(' ')
            guid_name = type_prefix + guid_name
            binary_pattern = make_binary_pattern(guid)

            ea = 0
            while True:
                ea = ida_bytes.find_bytes(binary_pattern, ea, flags=ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOSHOW)
                if ea == ida_idaapi.BADADDR:
                    break

                idc.del_items(ea, 16, 0)
                ida_bytes.create_struct(ea, 16, tid)
                if idc.set_name(ea, guid_name, ida_name.SN_NOWARN) != 1:
                    for i in range(0, 100):
                        if idc.set_name(ea, guid_name + "_" + str(i), ida_name.SN_NOWARN) == 1:
                            break
                    else:
                        print('[!] 0x{:X}: failed to apply {}'.format(ea, guid_name))
                print('[*] 0x{:X}: {}'.format(ea, guid_name))
                
                # add a byte size for find_bytes because it does not have SEARCH_NEXT option like find_binary
                ea += 1

    print('[*] finished')

if __name__ == "__main__":
    main()
