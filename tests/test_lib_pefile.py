#!/usr/bin/env python

from __future__ import print_function

# sys.path.insert(1,r'C:\Users\rchateau\Developpement\ReverseEngineeringApps\PythonStyle\survol\revlib')

import os
import re
import sys
import unittest

from init import *

update_test_path()

################################################################################

# If this does not work, it returns the input string.
# def UndecorateSymbol(strSym):
#     def UndecorateRaw(strSym):
#         undname = ctypes.windll.dbghelp.UnDecorateSymbolName
#         undname.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint, ctypes.c_uint]
#
#         sizBuf = 50
#         while True:
#             ptrBuf = ctypes.create_string_buffer("Hello", sizBuf)
#             sizActual = undname(strSym, ptrBuf, sizBuf, 0)
#             if sizActual < sizBuf - 2:
#                 return ptrBuf
#             sizBuf *= 2
#
#     strRaw = UndecorateRaw(strSym).value
#
#     strRaw = strRaw.replace("__thiscall ", "")
#
#     for subStr in ["private: ", "public: ", "protected: "]:
#         if strRaw.startswith(subStr):
#             strRaw = strRaw[len(subStr):]
#             break
#
#     return strRaw


tests_symbols_ok = [
    ("??$_Getvals@_W@?$time_get@DV?$istreambuf_iterator@DU?$char_traits@D@std@@@std@@@std@@IAEX_WABV_Locinfo@1@@Z",
     "void std::time_get<char,std::istreambuf_iterator<char,std::char_traits<char> > >::_Getvals<wchar_t>(wchar_t,std::_Locinfo const &)"),
    ("??$_Getvals@_W@?$time_get@GV?$istreambuf_iterator@GU?$char_traits@G@std@@@std@@@std@@IAEX_WABV_Locinfo@1@@Z",
     "void std::time_get<unsigned short,std::istreambuf_iterator<unsigned short,std::char_traits<unsigned short> > >::_Getvals<wchar_t>(wchar_t,std::_Locinfo const &)"),
    ("??$_Getvals@_W@?$time_get@_WV?$istreambuf_iterator@_WU?$char_traits@_W@std@@@std@@@std@@IAEX_WABV_Locinfo@1@@Z",
     "void std::time_get<wchar_t,std::istreambuf_iterator<wchar_t,std::char_traits<wchar_t> > >::_Getvals<wchar_t>(wchar_t,std::_Locinfo const &)"),
    ("??0?$_Yarn@D@std@@QAE@ABV01@@Z",
     "std::_Yarn<char>::_Yarn<char>(std::_Yarn<char> const &)"),
    ("??0?$_Yarn@D@std@@QAE@PBD@Z",
     "std::_Yarn<char>::_Yarn<char>(char const *)"),
    ("??0?$_Yarn@D@std@@QAE@XZ",
     "std::_Yarn<char>::_Yarn<char>(void)"),
    ("??0?$_Yarn@_W@std@@QAE@XZ",
     "std::_Yarn<wchar_t>::_Yarn<wchar_t>(void)"),
    ("??0?$basic_ios@DU?$char_traits@D@std@@@std@@IAE@XZ",
     "std::basic_ios<char,std::char_traits<char> >::basic_ios<char,std::char_traits<char> >(void)"),
    ("??0?$basic_ios@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z",
     "std::basic_ios<char,std::char_traits<char> >::basic_ios<char,std::char_traits<char> >(std::basic_streambuf<char,std::char_traits<char> > *)"),
    ("??0?$basic_ios@GU?$char_traits@G@std@@@std@@IAE@XZ",
     "std::basic_ios<unsigned short,std::char_traits<unsigned short> >::basic_ios<unsigned short,std::char_traits<unsigned short> >(void)"),
    ("??0?$basic_ios@GU?$char_traits@G@std@@@std@@QAE@PAV?$basic_streambuf@GU?$char_traits@G@std@@@1@@Z",
     "std::basic_ios<unsigned short,std::char_traits<unsigned short> >::basic_ios<unsigned short,std::char_traits<unsigned short> >(std::basic_streambuf<unsigned short,std::char_traits<unsigned short> > *)"),
    ("??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@IAE@XZ",
     "std::basic_ios<wchar_t,std::char_traits<wchar_t> >::basic_ios<wchar_t,std::char_traits<wchar_t> >(void)"),
    ("??0?$basic_ios@_WU?$char_traits@_W@std@@@std@@QAE@PAV?$basic_streambuf@_WU?$char_traits@_W@std@@@1@@Z",
     "std::basic_ios<wchar_t,std::char_traits<wchar_t> >::basic_ios<wchar_t,std::char_traits<wchar_t> >(std::basic_streambuf<wchar_t,std::char_traits<wchar_t> > *)"),
    ("??0?$basic_iostream@DU?$char_traits@D@std@@@std@@QAE@PAV?$basic_streambuf@DU?$char_traits@D@std@@@1@@Z",
     "std::basic_iostream<char,std::char_traits<char> >::basic_iostream<char,std::char_traits<char> >(std::basic_streambuf<char,std::char_traits<char> > *)"),
    ("??0?$basic_iostream@GU?$char_traits@G@std@@@std@@QAE@PAV?$basic_streambuf@GU?$char_traits@G@std@@@1@@Z",
     "std::basic_iostream<unsigned short,std::char_traits<unsigned short> >::basic_iostream<unsigned short,std::char_traits<unsigned short> >(std::basic_streambuf<unsigned short,std::char_traits<unsigned short> > *)"),
    ]

tests_symbols_failed = [
    "??0?$basic_iostream@DU?$char_traits@D@std@@@std@@IAE@$$QAV01@@Z",
    "??0?$basic_iostream@GU?$char_traits@G@std@@@std@@IAE@$$QAV01@@Z",
    "??0?$basic_iostream@_WU?$char_traits@_W@std@@@std@@IAE@$$QAV01@@Z",
]



class PEFile_Test(unittest.TestCase):

    @unittest.skipIf(not is_platform_windows, "test_pefile for Windows only.")
    def test_pefile_ok(self):
        import lib_pefile
        for mangled_symbol, expected_output in tests_symbols_ok:
            undecorated_symbol = lib_pefile.UndecorateSymbol(mangled_symbol)
            print("in = ", mangled_symbol)
            print("out= ",undecorated_symbol)
            self.assertTrue(expected_output == undecorated_symbol)

    @unittest.skip("test_pefile_broken MUST BE FIXED.")
    def test_pefile_broken(self):
        import lib_pefile
        for mangled_symbol in tests_symbols_failed:
            undecorated_symbol = lib_pefile.UndecorateSymbol(mangled_symbol)
            print("in = ", mangled_symbol)
            print("out= ",undecorated_symbol)
            self.assertTrue(mangled_symbol != undecorated_symbol)


