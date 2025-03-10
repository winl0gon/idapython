import idautils
import idc
import idaapi
import re

def patch_disp(ea, delta):
    old_disp = idc.get_wide_dword(ea + 3)
    new_disp = (old_disp - delta) & 0xFFFFFFFF
    idc.patch_dword(ea + 3, new_disp)

def main():
    cur_ea = idc.here()
    func = idaapi.get_func(cur_ea)
    if not func:
        return

    start = func.start_ea
    end = func.end_ea
    count = 0

    pattern = re.compile(r"lea\s+rsi,\s+(\S+)\+([0-9A-Fa-f]+)h")

    for head in idautils.Heads(start, end):
        disasm_line = idc.generate_disasm_line(head, 0)
        if not disasm_line:
            continue

        m = pattern.search(disasm_line)
        if m:
            symbol = m.group(1)  # Symbol
            offset_str = m.group(2)  # Offset
            try:
                offset_val = int(offset_str, 16)
            except Exception as e:
                continue

            patch_disp(head, offset_val)
            count += 1

    print("count: %d" % count)

if __name__ == '__main__':
    main()

