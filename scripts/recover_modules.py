from ida_imports import *


ida_idaapi.require("utils")


def find_entry_point():
    main_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "modulecode___main__")
    if main_ea == ida_idaapi.BADADDR:
    
        # Locate `modulecode___main__` using the "__main__" string
        xrefs = utils.find_string_xrefs("__main__")
        assert len(xrefs) >= 2
        prev_xref = xrefs[0]
        for curr_xref in xrefs[1:]:
            func_ea = ida_funcs.get_func(curr_xref.frm).start_ea
            
            # rename function & set its type definition
            if ida_name.get_name(func_ea) in ["main", "WinMain"]:
                main_ea = ida_funcs.get_func(prev_xref.frm).start_ea 
                utils.set_filtered_name(main_ea, f"modulecode___main__")
                utils.set_type(main_ea, "modulecode")
                return main_ea
            prev_xref = curr_xref
    return main_ea


def find_custom_modules():
    """Locate custom modules & rename them to `modulecode_xxx` (except main module)"""
    # find loadConstantsBlob using its error string (if FLIRT fails)
    ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "loadConstantsBlob")
    if ea == ida_idaapi.BADADDR:
        xref = utils.find_sole_string_xref("Error, corrupted constants object")
        ea = ida_funcs.get_func(xref).start_ea
        utils.set_filtered_name(ea, f"loadConstantsBlob")
    utils.set_type(ea, "loadConstantsBlob")
    
    # get arguments of loadConstantsBlob(ts, mod_consts, module_name)
    module_data = {}
    for xref in idautils.XrefsTo(ea):
        if args_ea := ida_typeinf.get_arg_addrs(xref.frm):
            second_arg_ea = args_ea[1]  # rdx, mod_consts
            third_arg_ea = args_ea[2]  # r8, <module_name>
            
            mod_consts_rva = idc.get_operand_value(second_arg_ea, 1) - ida_nalt.get_imagebase()
            module_name_ea = idc.get_operand_value(third_arg_ea, 1)
            module_name_rva = module_name_ea - ida_nalt.get_imagebase()
            module_name = ida_bytes.get_strlit_contents(module_name_ea, -1, ida_nalt.STRTYPE_C)
            if module_name:
                module_name = module_name.decode()
                if module_name != ".bytecode":  # ignore .bytecode module
                    func_ea = ida_funcs.get_func(xref.frm).start_ea
                    if module_name != "__main__":  # don't rename main module
                        module_name = utils.set_filtered_name(func_ea, module_name, prefix="modulecode")[11:]
                        utils.set_type(func_ea, "modulecode")
                    module_data[module_name] = (mod_consts_rva, module_name_rva)
    return module_data


if __name__ == "__main__":
    ida_kernwin.msg_clear()
    main_ea = find_entry_point()
    module_data = find_custom_modules()
    print(f"modulecode___main__: {hex(main_ea)}\n")
    for module_name in module_data:
        print("module_name:", module_name, end=" | ")
        mod_consts_rva, module_name_rva = module_data[module_name]
        print("mod_consts_rva:", hex(mod_consts_rva), end=" | ")
        print("module_name_rva:", hex(module_name_rva))
