from ida_imports import *
import ctypes
import struct


ida_idaapi.require("utils")

type_mappings = {
    "str": str,
    "bytes": bytes,
    "bytearray": bytearray,
    "int": int,
    "bool": bool,
    "float": float,
    "type": type,
    "NoneType": type(None),
    "None": None,
    "range": range,
    "slice": slice,
    "list": list,
    "tuple": tuple,
    "set": set,
    "dict": dict,
}

scalar_data_types = ["str", "bytes", "bytearray", "int", "bool", "float", "type", "NoneType", "module"]
collection_data_types = ["range", "slice", "list", "tuple", "set", "dict"]


def convert_nested_lists_to_tuples(const):
    if type(const) == list:
        return tuple(convert_nested_lists_to_tuples(item) for item in const)
    return const


def comment_range_constant(curr_ea, const):
    """
    Simplify range() using these rules before commenting:
    1. Change range(x, y, 1) to range(x, y)
    2. Change range(0, y) to range(y)
    """
    if const[2] == 1:  # range(x, y, 1) -> range(x, y)
        ida_bytes.set_cmt(curr_ea, f"range{const[:2]}", 0)
        
        if const[0] == 0:  # range(0, y, 1) -> range(y)
            ida_bytes.set_cmt(curr_ea, f"range({const[1]})", 0)
            
    else:  # range(x, y, z)
        ida_bytes.set_cmt(curr_ea, f"range{const}", 0)        


def comment_slice_constant(curr_ea, const):
    # similar logic to comment_range_object
    if const[0] == 0:
        const[0] = None
    if const[2] == 1:
        const[2] = None
    ida_bytes.set_cmt(curr_ea, str(const).replace("None", "").replace(", ", ":"), 0)
    
    
def convert_back_collection(collection, index_lst, constant_type):
    """Convert substitute lists back to tuple/set based on indexes"""
    i = index_lst[0]
    if len(index_lst) == 1:
        if constant_type == tuple:
            collection[i] = tuple(collection[i])
        elif constant_type == set:
            collection[i] = set(collection[i])
    else:  # traverse list
        convert_back_collection(collection[i], index_lst[1:], constant_type)


def add_item_to_collection(const, collection, stack_depth, tracked_indexes, dict_field):
    temp = collection
    index_lst = []  # track indexes of collection
    if dict_field == "tuple_key":  # access key instead of value
        stack_depth -= 1
    
    # iterate to the most recently inserted collection
    for i in range(stack_depth - 1):
        if type(temp) == dict:
            key = list(temp.keys())[-1]
            index_lst.append(key)
            temp = temp[key]
        else:
            i = len(temp) - 1  # positive index of last element
            index_lst.append(i)
            temp = temp[i]

    # substitute tuple/set with list as their properties (immutable/not subscriptable) make it troublesome to add elements
    substitute_collection = False
    original_type = type(const)
    if original_type == set or \
       original_type == tuple and dict_field != "tuple_key":  # tuple but not dict key
        substitute_collection = True
        const = list(const)
    
    # add constant to collection
    if type(temp) == dict:
        keys = list(temp.keys())
        key = keys[-1] if keys else None  # get last inserted key
        if dict_field.endswith("key"):
            temp[const] = None
        else:  # add value
            temp[key] = const
            index_lst.append(key)

    elif type(temp) == list:
        temp.append(const)
        index_lst.append(len(temp) - 1)
        
    if substitute_collection:
        tracked_indexes.append((stack_depth, index_lst, original_type))


def parse_module_constant(
        curr_ea, 
        max_count=1, 
        collection=None, 
        stack_depth=1, 
        tracked_indexes=None, 
        dict_field=None
    ):
    """
    Parse & recover module constant (recursively) based on its PyObject type.
    
    curr_ea: address of current constant
    max_count: number of items to parse at current depth of (nested) constant
    collection: list that holds the recovered constant
    stack_depth: indicates the current depth of `collection`
    tracked_indexes: contains the indexes of the items in `collection` were converted to tuple/set
    dict_field: specifies the type of dictionary constant we are dealing with (i.e. key, tuple_key, tuple_key_item or value)
    """
    
    # https://docs.python-guide.org/writing/gotchas/
    if collection is None:
        collection = []  # we use a list to hold the constant as it can reference to objects (useful for constants of collection data types)
        
    if tracked_indexes is None:  # "if not tracked_indexes" != work as it creates a new list when tracked_indexes = [],
        tracked_indexes = []     # messing up the references in the list since this function is recursive
    
    #print(hex(curr_ea))
    curr_count = 0
    while curr_count != max_count:
        mod_const = ida_bytes.get_qword(curr_ea)
        
        # check if address of constant is valid
        if not ida_ida.inf_get_min_ea() <= mod_const <= ida_ida.inf_get_max_ea():
            curr_ea += 8        
            curr_count += 1
            continue
        
        # get type from tp_name field in PyTypeObject
        type_obj_field = mod_const + 8
        type_obj = ida_bytes.get_qword(type_obj_field)
        
        tp_name_field = type_obj + 8*3  # https://pythoncapi.readthedocs.io/type_object.html
        tp_name = ida_bytes.get_qword(tp_name_field)

        const_type = ida_bytes.get_strlit_contents(tp_name, -1, ida_nalt.STRTYPE_C).decode()
        ida_bytes.create_qword(curr_ea, 8)
        
        # format PyObject structs & retrieve the constant values
        const = None
        if const_type == "str":  # PyUnicodeObject (see PyASCIIObject)
            utils.set_filtered_name(mod_const, "unicode_object")
            length_field = mod_const + 8*2
            string_field = mod_const + 8*6
            for i in range(6):  # format struct
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(length_field, "len", 0)
            ida_bytes.set_cmt(string_field, "str", 0)
            
            length = ida_bytes.get_qword(length_field)
            string = ida_bytes.get_strlit_contents(string_field, -1, ida_nalt.STRTYPE_C)

            if not string:
                if length != 0:  # unicode string (stored in a different field)
                    wstr_field = mod_const + 8*5
                    wstr = ida_bytes.get_bytes(ida_bytes.get_qword(wstr_field), length * 2).decode("utf-16")
                    string = "".join([f"\\u{ord(c):04x}" if ord(c) > 127 else c for c in wstr])
                    ida_bytes.create_strlit(string_field, length * 2, ida_nalt.STRTYPE_C_16)  
                else:  # empty string
                    string = ""
            else:  # ascii string
                string = string.decode()
                ida_bytes.create_strlit(string_field, length, ida_nalt.STRTYPE_C)  
            utils.set_filtered_name(curr_ea, string.replace("\\", "_"), prefix=const_type)
            const = string
        
        elif const_type == "bytes":  # PyBytesObject
            utils.set_filtered_name(mod_const, "bytes_object")
            length_field = mod_const + 8*2
            bytes_field = mod_const + 8*4
            for i in range(4):  # format struct
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(length_field, "len", 0)
            ida_bytes.set_cmt(bytes_field, "bytes", 0)
            length = ida_bytes.get_qword(length_field)  # get value
            
            bytestring = ida_bytes.get_bytes(bytes_field, length)
            if not bytestring:
                bytestring = b""
            
            # format bytes_field
            try:  # encoded string
                bytestring.decode()  # test for error
                ida_bytes.create_strlit(bytes_field, length, ida_nalt.STRTYPE_C)
            except:  # raw bytes
                idc.make_array(bytes_field, length)
            
            # format bytestring
            utils.set_filtered_name(curr_ea, str(bytestring)[2:-1].replace("\\", "_"), prefix=const_type)
            const = bytestring
        
        elif const_type == "bytearray":  # PyByteArrayObject
            utils.set_filtered_name(mod_const, "bytearray_object")
            size_field = mod_const + 8*2  # ob_size field
            bytearray_field = mod_const + 8*5  # ob_start field
            for i in range(7):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0)
            ida_bytes.set_cmt(bytearray_field, "bytearray", 0)
            size = ida_bytes.get_qword(size_field)
            bytearray_ptr = ida_bytes.get_qword(bytearray_field)
            byte_array = ida_bytes.get_bytes(bytearray_ptr, size)
            if not byte_array:
                byte_array = b""
            
            # format bytes_field
            try:  # encoded string
                byte_array.decode()  # test for error
                ida_bytes.create_strlit(bytearray_ptr, size, ida_nalt.STRTYPE_C)
            except:  # raw bytes
                idc.make_array(bytearray_ptr, size)
            
            # format byte_array
            utils.set_filtered_name(curr_ea, str(byte_array)[2:-1].replace("\\", "_"), prefix=const_type)
            const = bytearray(byte_array)

        elif const_type == "int":  # PyLongObject (typedef as _longobject)
            utils.set_filtered_name(mod_const, "long_object")
            lv_tag_field = mod_const + 8*2  
            ob_digit_field = mod_const + 8*3  # start of digit array
            for i in range(3):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(lv_tag_field, "lv_tag", 0)
            ida_bytes.set_cmt(ob_digit_field, "ob_digit", 0)
            
            # https://github.com/python/cpython/blob/main/Include/cpython/longintrepr.h#L64
            lv_tag = ctypes.c_long(ida_bytes.get_qword(lv_tag_field)).value 
            ndigits = abs(lv_tag)
            PyLong_SHIFT = 30  # 15 for 32-bit
            
            # format ob_digit array
            ida_bytes.del_items(ob_digit_field, ida_bytes.DELIT_EXPAND)
            ida_bytes.create_dword(ob_digit_field, 4)
            idc.make_array(ob_digit_field, ndigits)
            
            _sum = 0
            for i in range(ndigits):
                ob_digit_i = ida_bytes.get_dword(ob_digit_field + 4*i)
                _sum += ob_digit_i * 2**(PyLong_SHIFT*i)
            
            if lv_tag < 0:
                _sum *= -1
            
            utils.set_filtered_name(curr_ea, f"{_sum}", prefix=const_type)
            const = _sum
            
        elif const_type == "bool":  # PyBoolObject (typedef as PyLongObject)
            utils.set_filtered_name(mod_const, "bool_object")
            digit_field = mod_const + 8*3
            for i in range(4):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(digit_field, "bool", 0)
            
            boolean = ida_bytes.get_dword(digit_field)
            boolean = True if boolean == 1 else False
            utils.set_filtered_name(curr_ea, f"{boolean}", prefix=const_type)
            const = boolean
        
        elif const_type == "float":  # PyFloatObject
            utils.set_filtered_name(mod_const, "float_object")
            double_field = mod_const + 8*2
            for i in range(3):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(double_field, "float", 0)
            double = struct.unpack("d", ida_bytes.get_bytes(double_field, 8))[0]  # bytes to double
            utils.set_filtered_name(curr_ea, f"{double}", prefix=const_type)
            const = double
        
        elif const_type == "range":  # rangeobject
            utils.set_filtered_name(mod_const, "range_object")
            start_field = mod_const + 8*2
            stop_field = mod_const + 8*3
            step_field = mod_const + 8*4
            for i in range(6):  # format struct
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(start_field, "start", 0)
            ida_bytes.set_cmt(stop_field, "stop", 0)
            ida_bytes.set_cmt(step_field, "step", 0)
            
            add_item_to_collection((), collection, stack_depth,  tracked_indexes, dict_field)
            parse_module_constant(start_field, 3, collection, stack_depth + 1, tracked_indexes, dict_field) 
        
        elif const_type == "slice":  # PySliceObject (rangeobject without the length field)
            utils.set_filtered_name(mod_const, "slice_object")
            start_field = mod_const + 8*2
            stop_field = mod_const + 8*3
            step_field = mod_const + 8*4
            for i in range(5):  # format struct
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(start_field, "start", 0)
            ida_bytes.set_cmt(stop_field, "stop", 0)
            ida_bytes.set_cmt(step_field, "step", 0)
            
            add_item_to_collection([], collection, stack_depth,  tracked_indexes, dict_field)
            parse_module_constant(start_field, 3, collection, stack_depth + 1, tracked_indexes, dict_field) 
            
        elif const_type == "list":  # PyListObject
            utils.set_filtered_name(mod_const, "list_object")
            size_field = mod_const + 8*2
            list_field = mod_const + 8*3  # ob_item field
            for i in range(5):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0)
            ida_bytes.set_cmt(list_field, "list", 0)
                
            # format & retrieve objects in list recursively
            size = ida_bytes.get_qword(size_field)
            list_ptr = ida_bytes.get_qword(list_field)
            utils.set_filtered_name(list_ptr, "ob_item")
            
            add_item_to_collection([], collection, stack_depth,  tracked_indexes, dict_field)
            parse_module_constant(list_ptr, size, collection, stack_depth + 1,  tracked_indexes, dict_field)
        
        elif const_type == "tuple":  # PyTupleObject
            utils.set_filtered_name(mod_const, "tuple_object")
            size_field = mod_const + 8*2
            tuple_field = mod_const + 8*3  # start of tuple
            for i in range(3):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0)
            
            size = ida_bytes.get_qword(size_field)
            for i in range(size):
                ida_bytes.set_cmt(tuple_field + 8*i, f"item[{i}]", 0)  # tuple items
            
            if dict_field == "key":  # treat tuple key as a SINGLE constant by building the ENTIRE key before adding it to the collection
                tuple_key = convert_nested_lists_to_tuples(parse_module_constant(curr_ea, 1, dict_field="tuple_key_item"))
                dict_field = "tuple_key"
                add_item_to_collection(tuple_key, collection, stack_depth + 1, tracked_indexes, dict_field)
            else:
                add_item_to_collection((), collection, stack_depth, tracked_indexes, dict_field)
            
            if dict_field != "tuple_key":
                parse_module_constant(tuple_field, size, collection, stack_depth + 1, tracked_indexes, dict_field)
            
        elif const_type == "set":  # PySetObject
            utils.set_filtered_name(mod_const, "set_object")
            size_field = mod_const + 8*3
            set_field = mod_const + 8*5  # table field
            for i in range(25):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(size_field, "size", 0)
            ida_bytes.set_cmt(set_field, "set", 0)
            
            size = ida_bytes.get_qword(size_field)
            set_ptr = ida_bytes.get_qword(set_field)
            utils.set_filtered_name(set_ptr, "table")
            
            add_item_to_collection(set(), collection, stack_depth, tracked_indexes, dict_field)
            
            count = 0
            entry = set_ptr
            while count < size:
                key_field = entry
                hash_field = entry + 8
                
                # https://github.com/python/cpython/blob/main/Include/cpython/setobject.h#L5
                if ida_bytes.get_qword(key_field) != 0:  # check if active key
                    ida_bytes.set_cmt(key_field, "entry", 0)
                    
                    parse_module_constant(key_field, 1, collection, stack_depth + 1, tracked_indexes, dict_field)
                    count += 1
                
                # format setentry struct
                ida_bytes.create_qword(key_field, 8)
                ida_bytes.create_qword(hash_field, 8)
                entry += 16
                
        elif const_type == "dict":  # PyDictObject
            utils.set_filtered_name(mod_const, "dict_object")
            ma_keys_field = mod_const + 8*4
            ma_values_field = mod_const + 8*5  # assume null (unimplemented for split table)
            for i in range(5):
                ida_bytes.create_qword(mod_const + 8*i, 8)

            add_item_to_collection({}, collection, stack_depth, tracked_indexes, dict_field)
            
            if ida_bytes.get_qword(ma_values_field) == 0:  # combined table
                ida_bytes.set_cmt(ma_keys_field, "dict", 0)
                ma_keys = ida_bytes.get_qword(ma_keys_field)
                utils.set_filtered_name(ma_keys, "ma_keys")
                
                dk_size_field = ma_keys + 8
                dk_nentries_field = ma_keys + 8*4
                dk_indices_field = ma_keys + 8*5
                
                ida_bytes.set_cmt(dk_size_field, "dk_size", 0)
                ida_bytes.set_cmt(dk_nentries_field, "dk_nentries", 0)
                
                dk_size = ctypes.c_long(ida_bytes.get_qword(ma_keys + 8)).value  # number of indices
                dk_nentries = ida_bytes.get_qword(ma_keys + 8*4)  # number of entries
                
                if dk_size == -1:  # empty dict
                    curr_ea += 8        
                    curr_count += 1
                    continue
                
                for i in range(6):
                    ida_bytes.create_qword(ma_keys + 8*i, 8)
                
                # https://github.com/python/cpython/blob/main/Objects/dictobject.c
                if dk_size <= 128:
                    index_size = 1
                elif 256 <= dk_size <= 2**15:
                    index_size = 2
                elif 2**16 <= dk_size <= 2**31:
                    index_size = 4
                elif 2**32 <= dk_size:
                    index_size = 8
                
                hashtable_size = dk_size * index_size
                idc.make_array(dk_indices_field, hashtable_size // 8)
                
                # parse PyDictKeyEntry entries (i.e. hash, key, value)
                dk_entries = dk_indices_field + hashtable_size
                for i in range(dk_nentries):
                    hash_field = dk_entries + 24*i
                    key_field = dk_entries + 24*i + 8
                    value_field = dk_entries + 24*i + 8*2
                    
                    ida_bytes.create_qword(hash_field, 8)
                    ida_bytes.set_cmt(key_field, "key", 0)
                    ida_bytes.set_cmt(value_field, "value", 0)

                    # get key-value pair
                    parse_module_constant(key_field, 1, collection, stack_depth + 1, tracked_indexes, "key")
                    parse_module_constant(value_field, 1, collection, stack_depth + 1, tracked_indexes, "value")
            #else: print(f"dictionary (split table) at {hex(curr_ea)} is currently unsupported")
                
        elif const_type == "type":  # PyTypeObject
            tp_name_field = mod_const + 8*3  # https://pythoncapi.readthedocs.io/type_object.html
            tp_name = ida_bytes.get_qword(tp_name_field)
            python_type = ida_bytes.get_strlit_contents(tp_name, -1, ida_nalt.STRTYPE_C).decode()
            utils.set_filtered_name(curr_ea, f"{python_type}", prefix=const_type)
            
            if python_type in type_mappings:
                const = type_mappings[python_type]
            #else: print(f"{python_type} type at {hex(curr_ea)} is currently unsupported")  # Nuitka type / unsupported Python type
                
        elif const_type == "NoneType":  # corresponds to None (not NoneType)
            utils.set_filtered_name(curr_ea, "type_None")
            const = None
        
        elif const_type == "module":  # PyModuleObject
            utils.set_filtered_name(mod_const, "module_object")
            module_name_field = mod_const + 8*6  # md_name field
            for i in range(7):
                ida_bytes.create_qword(mod_const + 8*i, 8)
            ida_bytes.set_cmt(module_name_field, "module name", 0)
            
            name_object = ida_bytes.get_qword(module_name_field)
            utils.set_filtered_name(name_object, "md_name")
            module_name = ida_bytes.get_strlit_contents(name_object + 8*6, -1, ida_nalt.STRTYPE_C)
            module_name = module_name.decode() if module_name else ""
            utils.set_filtered_name(curr_ea, f"{module_name}", prefix=const_type)
            const = f"module {module_name}"
            
        else:
            #print(f"'{const_type}' object at {hex(curr_ea)} is currently unsupported")
            if stack_depth == 1:
                utils.set_filtered_name(curr_ea, f"{const_type}")
                utils.set_filtered_name(mod_const, "object", prefix=const_type)
        
        # add scalar constant to collection
        if const_type in scalar_data_types:
            add_item_to_collection(const, collection, stack_depth, tracked_indexes, dict_field)
        
        # finished recovered constant
        if stack_depth == 1:  
        
            # comment & rename collection constant (i.e. constant of collection data type)
            if const_type in collection_data_types:
                
                # convert inner lists back to tuple/set
                tracked_indexes.sort(reverse=True)  # sort by highest stack depth to avoid working on tuples/sets
                for item in tracked_indexes:
                    _, index_lst, original_type = item
                    convert_back_collection(collection, index_lst, original_type)

                # set const to collection constant
                const = collection[0]

                # comment collection constant
                if const_type == "range":
                    comment_range_constant(curr_ea, const)
                elif const_type == "slice":
                    comment_slice_constant(curr_ea, const)
                else:
                    ida_bytes.set_cmt(curr_ea, f"{const}", 0)
                
                # rename collection constant
                if not (const_type == "dict" and const and next(iter(const)) == "__name__"):
                    utils.set_filtered_name(curr_ea, f"{const}", prefix=const_type)
                else:  # rename module dictionary (heuristic: first dict key is "__name__")
                    moduledict_name = f"moduledict_{const['__name__']}"
                    print(f"[{moduledict_name}]")
                    for key in const:
                        print(f"{key}: {const[key]}")
                    utils.set_filtered_name(curr_ea, f"{moduledict_name}")
                
            else:  # comment scalar constant
                if const_type == "str":
                    ida_bytes.set_cmt(curr_ea, f"'{const}'", 0)
                else:
                    ida_bytes.set_cmt(curr_ea, f"{const}", 0)

        curr_ea += 8        
        curr_count += 1
    if collection:
        return collection[0]
    return None
    
    
def parse_module_constants(curr_ea=ida_kernwin.get_screen_ea(), max_count=None):
    """Parse address table of constants based on their PyObject type & recover their values"""
    constants = []
    curr_count = 0
    
    # break on invalid constant address
    while curr_count != max_count and ida_ida.inf_get_min_ea() <= ida_bytes.get_qword(curr_ea) <= ida_ida.inf_get_max_ea():
        constants.append(parse_module_constant(curr_ea))
        curr_ea += 8
        curr_count += 1
    return constants


if __name__ == "__main__":
    ida_kernwin.msg_clear()
    parse_module_constants()
