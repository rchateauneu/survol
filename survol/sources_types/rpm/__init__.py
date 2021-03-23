"""
RedHat Package Manager
"""

import rdflib
from rdflib.namespace import XSD

import rpm

import lib_uris
import lib_util
import lib_common

def EntityOntology():
    return (["Rpm",],)


def MakeUri(rpm_name):
    return lib_uris.gUriGen.UriMakeFromDict("rpm", {"Rpm": rpm_name})


def EntityName(entity_ids_arr):
    return entity_ids_arr[0]


def RpmProps():
    list_props = ["epoch", "version", "release", "arch"]

    # Add a dot, so they come first.
    rpm_props = {propKey: lib_common.MakeProp("." + propKey) for propKey in list_props}

    return rpm_props


def AddInfo(grph, node, entity_ids_arr):
    rpm_name = entity_ids_arr[0]

    rpm_props = RpmProps()

    ts = rpm.TransactionSet()
    mi = ts.dbMatch('name',rpm_name)
    for h in mi:
        for prop_key in rpm_props:
            prop_rpm = rpm_props[prop_key]
            # The value might be None.
            prop_val = h[prop_key] or ""
            grph.add((node, prop_rpm, lib_util.NodeLiteral(prop_val)))




