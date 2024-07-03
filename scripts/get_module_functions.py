import sys
import inspect
from pathlib import Path


modules = ["__main__", "flag"]  # EDIT THIS
log_file = "functions.log"


def get_module_functions(module_name):
    if module_name not in sys.modules:
        return
    
    with open(log_file, "a") as f:
        f.write(f"[{module_name}]\n")
        funcs = inspect.getmembers(sys.modules[module_name], inspect.isfunction)
        for func_name, func_obj in funcs:
            signature = inspect.signature(func_obj)
            params = [(name, value.default) if value.default != inspect.Parameter.empty else (name, None) for name, value in signature.parameters.items()]
            if func_name != "get_module_functions":
                f.write(f"{func_name}{signature}\n")
        f.write("\n")


Path(log_file).unlink(True)  # reset log file
for module in modules:
    get_module_functions(module)
