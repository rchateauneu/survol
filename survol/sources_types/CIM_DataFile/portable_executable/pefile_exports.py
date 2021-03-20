#!/usr/bin/env python

"""
Pefile exports
"""

# BEWARE: Do NOT rename it as stat.py otherwise strange errors happen,
# probably a collision of modules names, with the message:
# "Fatal Python error: Py_Initialize: can't initialize sys standard streams"

import os
import sys
import time
import logging
import lib_util
import lib_uris
import lib_common
import lib_properties
from lib_properties import pc

# This can work only on Windows and with exe files.
import pefile
import lib_pefile


def _pefile_decorate(grph, root_node, pe):
    """Not used yet."""
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    #UnicodeEncodeError: 'ascii' codec can't encode character u'\xa9' in position 16: ordinal not in range(128)
                    # sys.stderr.write("%s %s\n"% (entry[0], entry[1]) )
                    key = entry[0]
                    val = entry[1]
                    if val is None:
                        val = "None"
                    else:
                        val = val.encode("ascii", errors="replace")
                    grph.add((root_node, lib_common.MakeProp(key), lib_util.NodeLiteral(val)))
        return


def Main():
    cgiEnv = lib_common.ScriptEnvironment()
    fil_nam = cgiEnv.GetId()
    logging.debug("fil_nam=%s", fil_nam)

    fil_node = lib_common.gUriGen.FileUri(fil_nam)

    try:
        pe = pefile.PE(fil_nam)
    except Exception as exc:
        lib_common.ErrorMessageHtml("File: %s. Exception:%s:" % (fil_nam, str(exc)))

    # sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.Length) )
    # sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.Type) )
    # sys.stderr.write("%s\n" % hex(pe.VS_VERSIONINFO.ValueLength) )
    # sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.Signature) )
    # sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.FileFlags) )
    # sys.stderr.write("%s\n" % hex(pe.VS_FIXEDFILEINFO.FileOS) )
    # for fileinfo in pe.FileInfo:
    #     if fileinfo.Key == 'StringFileInfo':
    #         for st in fileinfo.StringTable:
    #             for entry in st.entries.items():
    #                 #UnicodeEncodeError: 'ascii' codec can't encode character u'\xa9' in position 16: ordinal not in range(128)
    #                 # sys.stderr.write("%s %s\n"% (entry[0], entry[1]) )
    #                 key = entry[0]
    #                 val = entry[1]
    #                 key = key
    #                 if val is None:
    #                     val = "None"
    #                 else:
    #                     val = val.encode("ascii", errors="replace")
    #                     # val = val.encode("utf-8", errors="replace")
    #                 # val = val[:2]
    #                 sys.stderr.write("%s %s\n"% (key,val) )
    #     elif fileinfo.Key == 'VarFileInfo':
    #         for var in fileinfo.Var:
    #             sys.stderr.write('%s: %s\n' % var.entry.items()[0] )
    #

    # If the PE file was loaded using the fast_load=True argument, we will need to parse the data directories:
    # pe.parse_data_directories()

    grph = cgiEnv.GetGraph()

    try:
        prop_forward = lib_common.MakeProp("Forward")
        prop_address = lib_common.MakeProp("Address")
        prop_ordinal = lib_common.MakeProp("Ordinal")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            decoded_sym_nam = lib_pefile.UndecorateSymbol(exp.name)
            sym_node = lib_uris.gUriGen.SymbolUri(decoded_sym_nam, fil_nam)
            grph.add((fil_node, pc.property_symbol_defined, sym_node))
            forward = exp.forwarder
            if not forward:
                forward = ""
            grph.add((sym_node, prop_forward, lib_util.NodeLiteral(forward)))
            grph.add((sym_node, prop_address, lib_util.NodeLiteral(hex(exp.address))))
            grph.add((sym_node, prop_ordinal, lib_util.NodeLiteral(hex(exp.ordinal))))
            # grph.add( ( sym_node, lib_common.MakeProp("Rest"), lib_util.NodeLiteral(dir(exp)) ) )
    except Exception as exc:
        lib_common.ErrorMessageHtml("File: %s. Exception:%s:" % (fil_nam, str(exc)))

    # cgiEnv.OutCgiRdf()
    # cgiEnv.OutCgiRdf("LAYOUT_TWOPI")
    cgiEnv.OutCgiRdf("LAYOUT_RECT", [pc.property_symbol_defined])


if __name__ == '__main__':
    Main()
