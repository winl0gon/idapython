# https://python.docs.hex-rays.com/
import idc
import ida_kernwin
import ida_ua
import ida_lines
import ida_nalt
import ida_bytes

key_value = ""
screen_ea = ida_kernwin.get_screen_ea()

insn = ida_ua.insn_t()
if ida_ua.decode_insn(insn, screen_ea):
    asm = idc.generate_disasm_line(insn.ea, 0)
    asm = ida_lines.tag_remove(asm)

if insn.get_canon_mnem() == "lea":
    op = insn.ops[1]
    if op.type == ida_ua.o_mem:
        string_address = op.addr
        result_string = ida_bytes.get_strlit_contents(string_address, -1, ida_nalt.STRTYPE_C)
        if result_string:
            target_string = result_string.decode('utf-8')

def decode_string(s: str, k: str):
    key = k
    result = []
    for c in s:
        if c in key:
            i = key.index(c)
            char = key[((i - 22) & 63)]
            result.append(char)
        else:
            result.append(c)
    return ''.join(result)

print(decode_string(target_string, key_value))