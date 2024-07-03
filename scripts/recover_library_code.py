from ida_imports import *
import ctypes


def load_structs(path=""):
    if not path: 
        path = ida_kernwin.ask_file(1, ".h", "Select C header file to parse")
        if not path:
            return
    
    idc.parse_decls(path, ida_typeinf.PT_FILE)
    ida_auto.auto_wait()


def load_flirt_signature(path=""):
    if not path:
        path = ida_kernwin.ask_file(1, ".sig", "Select FLIRT signature to load")
        if not path:
            return

    if "nuitka-flake.sig" in path:
        ctypes.windll.user32.MessageBoxA(
            0,
            b"Create your own Nuitka FLIRT signature for better results!",
            b"Using FLIRT signature for flake.exe",
            0x30
        )
    ida_funcs.plan_to_apply_idasgn(path)
    ida_auto.auto_wait()


if __name__ == "__main__":
    ida_kernwin.msg_clear()
    load_structs()
    load_flirt_signature()
