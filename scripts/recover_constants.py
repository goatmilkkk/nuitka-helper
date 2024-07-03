from ida_imports import *
from pathlib import Path
import time


ida_idaapi.require("utils")
ida_idaapi.require("recover_modules")
ida_idaapi.require("parse_module_constants")


def force_load_constants(module_data):
    """Load module constants by force using Appcall"""
    loadConstantsBlob = ida_idd.Appcall["loadConstantsBlob"]
    for module_name in module_data:  # convert rva to absolute
        mod_consts_rva, module_name_ea_rva = module_data[module_name]
        mod_consts = mod_consts_rva + ida_nalt.get_imagebase()
        module_name_ea = module_name_ea_rva + ida_nalt.get_imagebase()
        
        if module_name != "__main__":
            print(f"Loading constants for {module_name} ... ")
            loadConstantsBlob(0, mod_consts, module_name_ea)
        time.sleep(2)  # Appcall bug(?): IDA crashes w/o this (internal error 40731/unhandled c++ exception)
    ida_dbg.refresh_debugger_memory()
    print("")


def parse_all_constants(module_data, log_file="constants.log"):
    """Recover loaded constants in all modules & log them"""
    Path(log_file).unlink(True)  # reset log file
    with open(log_file, "a") as f:
        for module_name in module_data:
            f.write(f"{'-'*30} [modulecode_{module_name}] {'-'*30}\n")
            mod_consts = module_data[module_name][0] + ida_nalt.get_imagebase()
            try:
                constants = parse_module_constants.parse_module_constants(mod_consts)
                for constant in constants:
                    f.write(f"{constant}\n")
            except:
                print(f"[ERROR] Failed to recover constants for {module_name} ({hex(mod_consts)})")
            f.write("\n")
        
        
def recover_constants():
    # recover modules
    main_ea = recover_modules.find_entry_point()  # modulecode___main__
    module_data = recover_modules.find_custom_modules()  # modulecode_xxx

    # force-load constants & recover them
    ida_dbg.add_bpt(main_ea)
    utils.start_debugger()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    
    force_load_constants(module_data)  # note: this takes a while
    parse_all_constants(module_data)
    
    utils.stop_debugger()
    main_ea = recover_modules.find_entry_point()  # original main_ea might have changed due to ASLR
    ida_dbg.del_bpt(main_ea)
    ida_auto.auto_wait()


if __name__ == "__main__":
    ida_kernwin.msg_clear()
    recover_constants()
