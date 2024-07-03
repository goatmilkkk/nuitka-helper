from ida_imports import *
import re


ida_idaapi.require("utils")


def get_nuitka_version():
    # find createGlobalConstants using the "sentinel" string (if FLIRT fails)
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "createGlobalConstants")
    if ea == ida_idaapi.BADADDR:
        xref = utils.find_sole_string_xref("sentinel")
        ea = ida_funcs.get_func(xref).start_ea
    utils.set_filtered_name(ea, f"createGlobalConstants")
    
    # find Nuitka version using regex
    func = ida_funcs.get_func(ea)
    pseudocode = str(ida_hexrays.decompile(func))
    nuitka_version = ".".join([i.replace("i64", "").replace("LL", "") for i in re.findall("PyLong_FromLong\((.*?)\)", pseudocode)])
    if nuitka_version:
        print(f"Nuitka Version: {nuitka_version}")
    else:
        print("Nuitka Version: Not Found")
    

if __name__ == "__main__":
    ida_kernwin.msg_clear()
    get_nuitka_version()
