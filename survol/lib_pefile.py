import ctypes.wintypes
import six
import sys
import logging

import lib_util

undname = ctypes.windll.dbghelp.UnDecorateSymbolName
undname.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]


def UndecorateSymbol(str_sym):
    """
    If this does not work, it returns the input string.
    :param str_sym: Symbol name coming from PE, as bytes.
    :return: Clean symbol name.
    """
    assert isinstance(str_sym, six.binary_type)
    siz_buf = 200
    while True:
        ptr_buf = ctypes.create_string_buffer(b"", siz_buf)
        siz_actual = undname(str_sym, ptr_buf, siz_buf, 0)
        if siz_actual < siz_buf - 2:
            str_raw = ptr_buf.value
            break
        siz_buf *= 2

    # Now, some cleanup of useless strings. This tries to keep only the semantic information.
    for sub_str in [b"__thiscall ", b"__cdecl", b"class ", b"struct ", b" __ptr64"]:
        str_raw = str_raw.replace(sub_str, b"")

    for sub_str in [b"private: ", b"public: ", b"protected: "]:
        if str_raw.startswith(sub_str):
            str_raw = str_raw[len(sub_str):]
            break

    if lib_util.is_py3:
        str_raw = str_raw.decode()

    assert isinstance(str_raw, str)
    return str_raw

