#!/usr/bin/python

"""
Documentation of a COM type library entry
"""

import os
import sys
import rdflib
import lib_common
from lib_properties import pc

import win32con
import win32api

import lib_com_type_lib

Usable = lib_util.UsableWindows

cgiEnv = lib_common.CgiEnv()
fname_i = cgiEnv.GetId()

# Same structure for all entities. This is annoying but too early to have something more generic.
mtch_entry = re.mtch("(.*)_\(([0-9]*)\)")
if not mtch_entry:
	lib_common.ErrorMessageHtml

try:
	tlb = pythoncom.LoadTypeLib(fname)
except pythoncom.com_error:
	lib_common.ErrorMessageHtml("Cannot load:" + fname)


class HLITypeLibEntry(HLICOM):
    def GetText(self):
        tlb, index = self.myobject
        name, doc, ctx, helpFile = tlb.GetDocumentation(index)
        try:
            typedesc = HLITypeKinds[tlb.GetTypeInfoType(index)][1]
        except KeyError:
            typedesc = "Unknown!"
        return name + " - " + typedesc
    def GetSubList(self):
        tlb, index = self.myobject
        name, doc, ctx, helpFile = tlb.GetDocumentation(index)
        ret = []
        if doc: ret.append(browser.HLIDocString(doc, "Doc"))
        if helpFile: ret.append(HLIHelpFile(    (helpFile, ctx) ))
        return ret

# TODO: Finish this !
