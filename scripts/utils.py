from ida_imports import *
import re


definitions = {}

definitions["loadConstantsBlob"] = """
    void loadConstantsBlob(
        _ts *tstate,
        _object **mod_consts,
        char const *module_name
    );
"""

definitions["Nuitka_Function_New"] = """
    Nuitka_FunctionObject *Nuitka_Function_New(
        function_impl_code c_code, // function logic
        _object *name, // function name
        _object *qualname, 
        PyCodeObject *code_object, // code object
        _object *defaults, 
        _object *kw_defaults, 
        _object *annotations, 
        _object *module, 
        _object *doc, // function docstring
        struct Nuitka_CellObject **closure, 
        size_t closure_given
    );
"""

definitions["modulecode"] = """
    _object *module_initfunc(
        _ts *tstate,
        _object *module,
        const Nuitka_MetaPathBasedLoaderEntry *loader_entry
    );
"""


def find_string_xrefs(string):
    for s in idautils.Strings():
        if str(s) == string:
            return list(idautils.XrefsTo(s.ea))


def find_sole_string_xref(string):
    xrefs = find_string_xrefs(string)
    if not xrefs:
        raise Exception("No xrefs found")
    assert len(xrefs) == 1
    return xrefs[0].frm


def set_type(ea, type_name):
    # https://github.com/inforion/idapython-cheatsheet/blob/master/types/apply_types.py
    if type_name in definitions:
        type_name = definitions[type_name]
    _type = idc.parse_decl(type_name, ida_typeinf.TINFO_DEFINITE)
    if not _type:
        raise Exception("Missing Nuitka Structs")
    idc.apply_type(ea, _type, ida_typeinf.TINFO_DEFINITE)
    ida_auto.auto_wait()


def set_filtered_name(ea, name, prefix=None):
    # get range of invalid chars
    invalid_ranges = [match.span() for match in re.finditer("[^0-9a-zA-Z._]+", name)]
    strip_first_char = invalid_ranges and invalid_ranges[0][0] == 0
    strip_last_char = invalid_ranges and invalid_ranges[-1][-1] == len(name)
    
    # replace invalid chars w/ a single underscore from end to start (so that position of other characters are not affected)
    for start, end in invalid_ranges[::-1]:
        name = f"{name[:start]}_{name[end:]}"
    
    # strip leading & trailing underscores if they were originally invalid chars
    if strip_first_char:
        name = name[1:]
    if strip_last_char:
        name = name[:-1]
        
    if prefix:
        name = f"{prefix}_{name}"
    ida_name.set_name(ea, name, ida_name.SN_FORCE)
    return name


def start_debugger():
    ida_dbg.load_debugger("win32", 0)
    ida_dbg.start_process()


def stop_debugger():
    ida_dbg.exit_process()
    ida_dbg.wait_for_next_event(ida_dbg.dbg_process_exit, -1)
