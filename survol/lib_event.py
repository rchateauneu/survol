"""Stores and retrieves data related to an entity."""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__     = "GPL"

import os
import re
import sys
import time
import json
import unicodedata
import string
import lib_common
import lib_util
import lib_kbase
import traceback

# The directory where we store the events related to each object.
# "C:/Windows/Temp"
events_directory = lib_common.tmpDir + "/Events/"

# Files with this extension contains several lines,
# each line is a RDF-like triple, encoded in JSON,
# exactly as it was sent by the events generator.
events_file_extension = ".events"

# On Windows, forbidden base file names are:
# CON, PRN, AUX, NUL,
# COM1, COM2, COM3, COM4, COM5, COM6, COM7, COM8, COM9,
# LPT1, LPT2, LPT3, LPT4, LPT5, LPT6, LPT7, LPT8, and LPT9
def _string_to_filename(input_filename):
    filename_noslashes = re.sub(r'[/\\ \t\r\n]', '_', input_filename)
    filename_nobadchars = re.sub(r'[^-0-9a-zA-Z,=_.()-]', '', filename_noslashes)
    return filename_nobadchars


# This transforms an entity into a filename which is used to store the events
# related to this entity.
# This assumes that the properties are in the order of the ontology.
def _entity_type_ids_to_event_file(entity_type, entity_ids_dict):
    dirEntity = events_directory + entity_type
    if not os.path.isdir(dirEntity):
        os.mkdir(dirEntity)

    #sys.stderr.write("_entity_type_ids_to_event_file entity_type=%s\n"%entity_type)

    # Build a file name; where the event will be stored.

    # These are the properties which uniquely define the object.
    event_filename = entity_type
    delim = "."
    for attribute_name, attribute_value in entity_ids_dict.items():
        attribute_value = entity_ids_dict[attribute_name]
        # TODO: The value should probably be encoded and some characters escaped.
        event_filename += delim + "%s=%s" % (attribute_name, attribute_value)
        delim = ","

    #sys.stderr.write("_entity_type_ids_to_event_file eventFilNam=%s\n"%eventFilNam)

    # Windows filenames should not be too long.
    if len(event_filename) > 240:
        event_filename = event_filename[:240]

    # TODO: This is a temporary solution which should check the unicity of filenames
    # by adding a hash value at the end.

    eventFilNamLong = _string_to_filename(event_filename) + events_file_extension

    #sys.stderr.write("_entity_type_ids_to_event_file eventFilNamLong=%s\n"%eventFilNamLong)

    return eventFilNamLong

# There is one directory per entity type.
# Then, each entity has its own file whose name is the rest of the moniker.
def _moniker_to_event_filename(json_moniker):
    # The subject could be parsed with the usual functions made for moniker.
    entity_type = json_moniker["entity_type"]
    #sys.stderr.write("_moniker_to_event_filename entity_type=%s\n"%entity_type)

    entity_directory = events_directory + entity_type

    if not os.path.isdir(entity_directory):
        os.makedirs(entity_directory)

    #sys.stderr.write("_moniker_to_event_filename dirEntity=%s\n"%dirEntity)
    ontology_array = lib_util.OntologyClassKeys(entity_type)

    #sys.stderr.write("_moniker_to_event_filename arrOnto=%s\n"%str(arrOnto))
    entity_ids_dict = {}

    # Only the properties we need.
    for attribute_name in ontology_array:
        attribute_value = json_moniker[attribute_name]
        entity_ids_dict[attribute_name] = attribute_value

    event_created_filename = _entity_type_ids_to_event_file(entity_type, entity_ids_dict)

    #sys.stderr.write("_moniker_to_event_filename eventFilNam=%s\n"%eventFilNam)
    event_created_path = entity_directory + "/" + event_created_filename
    return event_created_path


def _add_event_to_file_of_object(object_moniker, json_events_triples):
    event_filename = _moniker_to_event_filename(object_moniker)
    # sys.stderr.write("_add_event_to_file_of_object eventFilNam=%s jsonData=%s\n"%(eventFilNam,str(jsonData)))
    # One JSON triple per line.

    # Try several times in case the script event_get.py would read at the same time.
    retries_number = 3
    sleep_delay = 0.5
    while retries_number > 0:
        retries_number -= 1
        try:
            # Appends a new event at the end.
            with open(event_filename, "a") as event_filedes:
                # This must be as fast as possible, so event_get is not blocked..
                json.dump(json_events_triples, event_filedes)
                event_filedes.write("\n")
                event_filedes.close()
            break
        except Exception as exc:
            sys.stderr.write("_add_event_to_file_of_object. Caught:%s\n" % str(exc))
            time.sleep(sleep_delay)
            sleep_delay *= 2
    if retries_number == 0:
        WARNING("_add_event_to_file_of_object %s leaving. Failed." % event_filename)


# This receives a json which has this structure:
# subject: A CIM object as a dictionary.
# predicate: A string.
# object: A literal or a CIM object, as a dictionary.
# This is practically a RDF triple, but it is not needed to import the rdflib module.
# This is based on json to move the strings, for convenience.
# It is not needed yet to load the ontology in the client.
def _store_event_triple(json_data):
    # sys.stderr.write("_store_event_triple entering.\n")
    # The subject is always there and telles where the data are stored.
    triple_subject = json_data["subject"]
    _add_event_to_file_of_object(triple_subject, json_data)
    #sys.stderr.write("_store_event_triple stored subject.\n")

    triple_object = json_data["object"]

    # Store the triple object if it is also a CIM url and not a literal.
    files_updates_number = 1
    if isinstance(triple_object, dict):
        _add_event_to_file_of_object(triple_object, json_data)
        files_updates_number += 1
    return files_updates_number


def store_events_triples_list(json_data_list):
    DEBUG("store_events_triples_list entering. Numtriples=%d.", len(json_data_list))
    files_updates_total_number = 0
    for json_data in json_data_list:
        try:
            files_updates_number = _store_event_triple(json_data)
            files_updates_total_number += files_updates_number
        except Exception as exc:
            WARNING("store_events_triples_list caught:%s. Json=%s", str(exc), str(json_data))
            traceback.print_exc()

    DEBUG("store_events_triples_list leaving.")
    return files_updates_total_number


def _triple_json_to_rdf(jsonTriple):
    def UrlJsonToTxt(valJson):
        entity_type = valJson["entity_type"]

        arrOnto = lib_util.OntologyClassKeys(entity_type)

        # Only the properties we need.
        entity_ids_dict = {ontoAttrNam: valJson[ontoAttrNam] for ontoAttrNam in arrOnto}

        return lib_common.gUriGen.UriMakeFromDict(entity_type, entity_ids_dict)

    valSubject = jsonTriple["subject"]
    txtSubject = UrlJsonToTxt(valSubject)

    valObject = jsonTriple["object"]

    # The object might be another CIM object or a literal.
    if isinstance(valObject, dict):
        txtObject = UrlJsonToTxt(valObject)
    else:
        txtObject = lib_kbase.MakeNodeLiteral(valObject)
        #sys.stderr.write("_store_event_triple stored object.\n")

    urlPred = lib_common.MakeProp(jsonTriple["predicate"])
    rdfTriple = (txtSubject, urlPred, txtObject)
    return rdfTriple


def _get_events_from_file(event_filename):
    # sys.stderr.write("_get_events_from_file eventFilNam=%s.\n"%eventFilNam)
    # Consider deleting the files if it is empty and not written to
    # for more than X hours, with os.fstat() and the member st_mtime

    # Try several times in case the script event_get.py would read at the same time.
    max_try = 3
    sleep_delay = 1
    triples_list = []
    while max_try > 0:
        max_try -= 1
        try:
            with open(event_filename, "r+") as event_filedes:
                # This must be as fast as possible, so event_put is not blocked.
                for line_json in event_filedes.readlines():
                    #sys.stderr.write("_get_events_from_file lineJson=%s.\n"%lineJson)
                    json_triple = json.loads(line_json)
                    # Now build Survol links which can be transformed in to valid RDF triples.
                    rdf_triple = _triple_json_to_rdf(json_triple)
                    triples_list.append(rdf_triple)

                event_filedes.seek(0)
                # TODO: BEWARE: WHY SHOULD WE DELETE OBJECTS IN THE GENERAL CASE ?
                # TODO: OR RATHER, THE INTERFACE SHOULD CHOOSE TO KEEP OBJECTS UNTIL THEY ARE EXPLICITLY DELETED ?
                event_filedes.truncate()
                event_filedes.close()
            break
        except Exception as exc:
            sys.stderr.write("_get_events_from_file failed event_filename=%s%s\n" % (event_filename, exc))
            # File locked or does not exist.
            time.sleep(sleep_delay)
            sleep_delay *= 2

    # sys.stderr.write("_get_events_from_file num triples=%d\n" % len(triples_list))
    return triples_list


def _retrieve_events_by_entity(entity_type, entity_ids_arr):
    DEBUG("_retrieve_events_by_entity entity_type=%s",entity_type)
    arrOnto = lib_util.OntologyClassKeys(entity_type)

    # Properties are in the right order.
    entity_ids_dict = dict(zip(arrOnto, entity_ids_arr))

    events_filepath = _entity_type_ids_to_event_file(entity_type, entity_ids_dict)

    DEBUG("_retrieve_events_by_entity events_filepath=%s", events_filepath)
    events_triples_list = _get_events_from_file(events_filepath)

    DEBUG("_retrieve_events_by_entity triples number=%d",len(events_triples_list))
    return events_triples_list


# TODO: The sane event might appear in two objects.
def retrieve_all_events():
    DEBUG("retrieve_all_events events_directory=%s", events_directory)

    triples_list = []
    for dirpath, dnames, fnames in os.walk(events_directory):
        for events_filename in fnames:
            #sys.stderr.write("retrieve_all_events filNam=%s\n"%filNam)
            if events_filename.endswith(events_file_extension):
                events_pathname = dirpath + "/" + events_filename
                #sys.stderr.write("retrieve_all_events pathNam=%s\n"%pathNam)
                triples_sublist = _get_events_from_file(events_pathname)
                triples_list.extend(triples_sublist)
    DEBUG("retrieve_all_events leaving with %d triples." % len(triples_list))
    return triples_list


def json_triples_to_rdf(json_triples, rdf_file_path):
    rdflib_graph = lib_kbase.MakeGraph()
    for tripl in json_triples:
        rdf_triple = _triple_json_to_rdf(tripl)
        rdflib_graph.add(rdf_triple)
    rdflib_graph.serialize(destination = rdf_file_path, format='pretty-xml')

