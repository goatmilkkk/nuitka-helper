from ida_imports import *
from pathlib import Path
import textwrap
import re


ida_idaapi.require("utils")
ida_idaapi.require("recover_functions")
ida_idaapi.require("parse_module_constants")

modules = ("__main__", "flag")  # specify which module functions to hook


def set_conditional_breakpoint(ea, cond):
    ida_dbg.add_bpt(ea)
    bpt = ida_dbg.bpt_t()
    ida_dbg.get_bpt(ea, bpt)
    bpt.elang = "Python"
    bpt.condition = cond
    ida_dbg.update_bpt(bpt)


def parse_code_object(ea):
    """Get function parameters from function code object"""
    # https://github.com/python/cpython/blob/3.10/Include/cpython/code.h
    co_argcount = ida_bytes.get_qword(ea + 8*2)
    co_varnames_field = ea + 8*9  # some fields in PyCode are sizeof(int)
    co_varnames = parse_module_constants.parse_module_constant(co_varnames_field)
    params = co_varnames[:co_argcount] if co_varnames else ()
    return params


def parse_function_object(ea):
    """Get name, parameters & docstring of Nuitka function"""
    # https://github.com/Nuitka/Nuitka/blob/main/nuitka/build/include/nuitka/compiled_function.h#L23
    m_doc = parse_module_constants.parse_module_constant(ea + 8*5)
    m_code_object = ida_bytes.get_qword(ea + 8*6)
    m_defaults = parse_module_constants.parse_module_constant(ea + 8*19)
    
    params = parse_code_object(m_code_object)
    default_args = m_defaults if m_defaults else ()
    docstring = m_doc if m_doc else ""
    return params, default_args, docstring


def hook_functions(modules):
    # find module functions
    for func_ea in idautils.Functions():
        func_name = ida_funcs.get_func_name(func_ea)  
        if func_name.startswith(modules) and func_name != "main":
        
            # hook function using conditional breakpoint    
            hook_code = """
                func_obj = idc.get_reg_value("rdx")
                func_args = idc.get_reg_value("r8")
                func_name = ida_name.get_name(idc.get_reg_value("rip"))

                params, default_args, docstring = parse_function_object(func_obj)
                args = tuple(parse_module_constants.parse_module_constants(func_args, len(params))) + default_args
                
                log_msg = f"{func_name}({', '.join([f'{params[i]}={args[i]}' for i in range(len(params))])})"
                if docstring:
                    log_msg += f" | docstring: '{docstring}'"
                    
                with open("trace.log", "a") as f:
                    f.write(f"{log_msg}\\n")
                return False  # returning True suspends the process
            """
            set_conditional_breakpoint(func_ea, textwrap.dedent(hook_code))


if __name__ == "__main__":
    ida_kernwin.msg_clear()
    Path("trace.log").unlink(True)  # reset log file
    utils.start_debugger()
    hook_functions(modules)
