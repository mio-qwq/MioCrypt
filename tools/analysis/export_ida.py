from pathlib import Path

import ida_auto
import ida_funcs
import ida_hexrays
import ida_lines
import idautils
import ida_nalt

ida_auto.auto_wait()
output_path = Path(__file__).resolve().parents[2] / "local" / "analysis" / "symbols" / "ida_export.txt"
output_path.parent.mkdir(parents=True, exist_ok=True)
terms = ("wWinMain", "StartsWithMagic", "GenerateSessionKey", "EncryptSessionKeyWithPublicKey", "XorEncryptInPlace", "EncryptFlagFile")
with open(output_path, "w", encoding="utf-8") as out:
    out.write("INPUT: %s\n" % ida_nalt.get_root_filename())
    out.write("\nFUNCTIONS:\n")
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea)
        if any(term in name for term in terms):
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
print("Wrote %s" % output_path)
