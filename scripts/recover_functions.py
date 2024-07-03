from ida_imports import *
import re


ida_idaapi.require("utils")
ida_idaapi.require("recover_modules")


def find_nuitka_function_new():
    """
    Find Nuitka_Function_New using heuristics:
    1. Child function of modulecode
    2. Has a total of 11 arguments
    3. First argument is a function
    
    
    Note: 
    - If the main module has no Python functions, Nuitka_Function_New will not be a child function of it, 
    possibly resulting in this function to be very time-consuming. 
    - In such cases, we can consider manually identifying Nuitka_Function_New instead (see blog).
    """
    # check if FLIRT has identified Nuitka_Function_New
    func_ea = ida_name.get_name_ea(ida_idaapi.BADADDR, "Nuitka_Function_New")
    if func_ea == ida_idaapi.BADADDR:
        
        # get list of module addresses (acts as fallback in case main module doesn't contain any Python functions)
        module_addrs = [recover_modules.find_entry_point(), ]
        for func_ea in idautils.Functions():
            func_name = ida_funcs.get_func_name(func_ea)
            if func_name.startswith("modulecode_") and not func_name.endswith("__main__"):
                module_addrs.append(func_ea)
        
        # identify Nuitka_Function_New using heuristics (if FLIRT fails)
        found = False 
        for module_ea in module_addrs:
            for item_ea in idautils.FuncItems(module_ea):
                if idc.print_insn_mnem(item_ea) == "call":

                    # get child function of modulecode
                    func_ea = idc.get_operand_value(item_ea, 0)
                    func = ida_funcs.get_func(func_ea)
                    
                    # check if `func_ea` is a function
                    if not (func and func.start_ea == func_ea):  
                        continue
                    
                    # decompile function to get type info
                    tif, func_data = ida_typeinf.tinfo_t(), ida_typeinf.func_type_data_t()
                    cfunc = ida_hexrays.decompile(func)
                    
                    cfunc.get_func_type(tif)
                    tif.get_func_details(func_data)
                    
                    # check child function has 11 arguments
                    if len(func_data) == 11:
                    
                        # apply type info
                        ida_typeinf.apply_tinfo(func_ea, tif, ida_typeinf.TINFO_GUESSED)  
                        ida_auto.auto_wait()
                        
                        # get address of arguments
                        arg_addrs = ida_typeinf.get_arg_addrs(item_ea) 
                        if not arg_addrs:
                            raise Exception(f"Failed to apply type definition at {hex(func_ea)}")
                        
                        # check first argument is a function
                        nuitka_func_ea = idc.get_operand_value(arg_addrs[0], 1)
                        nuitka_func = ida_funcs.get_func(nuitka_func_ea)
                        if nuitka_func and nuitka_func.start_ea == nuitka_func_ea:
                            found = True
                            utils.set_filtered_name(func_ea, f"Nuitka_Function_New")
                            break
            if found:
                break
    
        if not found:  # heuristics failed
            # this exception might get triggered if a program doesn't contain any Python functions at all
            # for such cases, just ignore the error, since it just means that this script isn't required
            raise Exception("Failed to find Nuitka_Function_New")
    
    utils.set_type(func_ea, "Nuitka_Function_New")
    return func_ea
    
    
def find_nuitka_functions():
    """Locate nuitka functions & rename them to func_xxx"""
    labelled_funcs = {}
    
    # get modules (some modules don't have functions)
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea)
        if func_name.startswith("modulecode_"):
            labelled_funcs[func_name[11:]] = []
    
    # check if xref to Nuitka_Function_New is in modulecode_xxx
    ea = find_nuitka_function_new()
    for xref in idautils.XrefsTo(ea):
        func = ida_funcs.get_func(xref.frm)
        if not func: continue
        module_func_name = ida_name.get_name(func.start_ea)
        if module_func_name.startswith("modulecode_"):
            module_name = module_func_name[11:]
        
            # get function name (second arg), and rename Nuitka function (first arg)
            if args_ea := ida_typeinf.get_arg_addrs(xref.frm):  
                func_code_ea = idc.get_operand_value(args_ea[0], 1)  # rcx, sub_xxx
                func_name_ea = idc.get_operand_value(args_ea[1], 1)  # rdx, <func_name>
                
                if ida_name.get_name(func_code_ea):  # check that function exists
                    func_name = ida_name.get_name(func_name_ea)
                    if func_name.startswith("str_"):  # check that function name has been recovered
                        func_name_cmt = ida_bytes.get_cmt(func_name_ea, 0)  # commented function name is more accurate as no suffix
                        func_name = f"{module_name}.{func_name_cmt[1:-1]}"
                        utils.set_filtered_name(func_code_ea, func_name)
                        
                        # map function to its module
                        func_name = ida_name.get_name(func_code_ea)  # in case of collisions
                        labelled_funcs[module_name].append(func_name)
                    else:
                        print(f"[ERROR] Failed to recover function name at {hex(func_name_ea)}")  # likely because script failed to parse constants
    return labelled_funcs


def group_nuitka_functions(labelled_funcs):
    # https://github.com/SentineLabs/AlphaGolang/blob/main/3.categorize_go_folders.py
    func_dir = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    for module_name in labelled_funcs:
        folder_name = module_name.replace(".", "/")  # create sub-folders
        func_dir.mkdir(folder_name)
        func_dir.rename(f"modulecode_{module_name}", f"{folder_name}/modulecode_{module_name}")  # rename module
        for func_name in labelled_funcs[module_name]:
            func_dir.rename(func_name, f"{folder_name}/{func_name}")  # rename module functions


if __name__ == "__main__":  # write to stdout for debugging
    ida_kernwin.msg_clear()
    labelled_funcs = find_nuitka_functions()
    group_nuitka_functions(labelled_funcs)
    for module_name in labelled_funcs:
        print(f"[{module_name}]")
        for func_name in labelled_funcs[module_name]:
            print(f"  {func_name}")
        print("")
