from pathlib import Path

import ida_auto, ida_funcs, ida_hexrays, ida_lines, ida_nalt, idautils, ida_entry, idc

ida_auto.auto_wait()
out_path = Path(__file__).resolve().parents[2] / "local" / "analysis" / "no-symbols" / "ida_nopdb_export.txt"
out_path.parent.mkdir(parents=True, exist_ok=True)
start, end = 0x140001000, 0x140002000
with open(out_path, "w", encoding="utf-8") as out:
    out.write("INPUT: %s\n" % ida_nalt.get_root_filename())
    out.write("\nENTRY POINTS:\n")
    for index, ordinal, ea, name in idautils.Entries():
        out.write("index=%d ordinal=%d 0x%X %s\n" % (index, ordinal, ea, name))
    out.write("\nFUNCTIONS (IDA auto names; PDB absent):\n")
    for ea in idautils.Functions(start, end):
        name = ida_funcs.get_func_name(ea)
        out.write("\n/* %s @ 0x%X */\n" % (name, ea))
        try:
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                out.write("\n".join(ida_lines.tag_remove(line.line) for line in cfunc.get_pseudocode()))
                out.write("\n")
            else:
                out.write("// no pseudocode\n")
        except Exception as exc:
            out.write("// decompile failed: %s\n" % exc)
    out.write("\nIMPORTS:\n")
    for ea, name in idautils.Names():
        if "idata" in (idc.get_segm_name(ea) or "").lower():
            out.write("0x%X %s\n" % (ea, name))
    out.write("\nSTRINGS:\n")
    for s in idautils.Strings():
        out.write("0x%X %s\n" % (s.ea, str(s)))
print("Wrote %s" % out_path)
