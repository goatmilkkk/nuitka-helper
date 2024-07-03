import ida_idaapi
import time


ida_idaapi.require("utils")
ida_idaapi.require("recover_library_code")
ida_idaapi.require("recover_modules")
ida_idaapi.require("recover_constants")
ida_idaapi.require("recover_functions")


def main():
    # recover symbols
    recover_library_code.load_structs()
    recover_library_code.load_flirt_signature()

    # recover modules
    main_ea = recover_modules.find_entry_point()  # modulecode___main__
    module_data = recover_modules.find_custom_modules()  # modulecode_xxx

    # recover constants
    recover_constants.recover_constants()
    
    # recover functions
    labelled_funcs = recover_functions.find_nuitka_functions()  # note: this may be time-consuming
    recover_functions.group_nuitka_functions(labelled_funcs)


if __name__ == "__main__":
    main()
