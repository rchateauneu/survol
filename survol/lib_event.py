"""Stores and retrieves data related to an entity."""

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020, Primhill Computers"
__license__     = "GPL"

import os
import re
import sys
import six
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
events_directory = lib_common.global_temp_directory + "/Events/"

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

    # TODO: check the unicity of filenames by adding a hash value at the end.

    event_full_filepath= _string_to_filename(event_filename) + events_file_extension
    return event_full_filepath


def json_moniker_to_entity_class_and_dict(json_moniker):
    assert len(json_moniker) == 2
    entity_type, entity_attributes_dict = json_moniker
    assert isinstance(entity_type, (six.binary_type, six.text_type))
    assert isinstance(entity_attributes_dict, dict)

    ontology_list = lib_util.OntologyClassKeys(entity_type)

    # TODO: Only the properties we need. In fact, they should come in the right order.
    # TODO: Make this faster by assuming this is a list of key-value pairs.
    entity_ids_dict = {ontology_attribute_name: entity_attributes_dict[ontology_attribute_name]
                       for ontology_attribute_name in ontology_list}
    return entity_type, entity_ids_dict


# There is one directory per entity type.
# Then, each entity has its own file whose name is the rest of the moniker.
def _moniker_to_event_filename(json_moniker):
    entity_type, entity_ids_dict = json_moniker_to_entity_class_and_dict(json_moniker)

    # The subject could be parsed with the usual functions made for moniker.
    entity_directory = events_directory + entity_type

    if not os.path.isdir(entity_directory):
        os.makedirs(entity_directory)

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
    if isinstance(triple_object, (list, tuple)):
        _add_event_to_file_of_object(triple_object, json_data)
        files_updates_number += 1
    return files_updates_number


def store_events_triples_list(json_data_list):
    files_updates_total_number = 0
    for json_data in json_data_list:
        try:
            files_updates_number = _store_event_triple(json_data)
            files_updates_total_number += files_updates_number
        except Exception as exc:
            WARNING("store_events_triples_list caught:%s. Json=%s", str(exc), str(json_data))
            traceback.print_exc()

    return files_updates_total_number


# Transforms a triple in JSON representation, into the rdflib triple.
def _triple_json_to_rdf(input_json_triple):
    def url_json_to_txt(json_value):
        entity_type, entity_ids_dict = json_moniker_to_entity_class_and_dict(json_value)

        return lib_common.gUriGen.UriMakeFromDict(entity_type, entity_ids_dict)

    subject_value_json = input_json_triple["subject"]
    subject_value_text = url_json_to_txt(subject_value_json)

    object_value_json = input_json_triple["object"]

    # The object might be another CIM object or a literal.
    # We should check the form: ("string", {})
    if isinstance(object_value_json, tuple) and len(object_value_json) == 2:
        object_value_text = url_json_to_txt(object_value_json)
    else:
        object_value_text = lib_kbase.MakeNodeLiteral(object_value_json)
        #sys.stderr.write("_store_event_triple stored object.\n")

    url_predicate = lib_common.MakeProp(input_json_triple["predicate"])
    rdf_triple = (subject_value_text, url_predicate, object_value_text)
    return rdf_triple


# This reads events from a file, then deletes them, so they can be read once only.
# TODO: Maybe keep an history ?
def _get_events_from_file(event_filename):
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
                    #sys.stderr.write("_get_events_from_file line_json=%s.\n"%line_json)
                    json_triple = json.loads(line_json)
                    # Now build Survol links which can be transformed in to valid RDF triples.
                    rdf_triple = _triple_json_to_rdf(json_triple)
                    triples_list.append(rdf_triple)

                file_was_empty = len(triples_list) == 0
                if not file_was_empty:
                    event_filedes.seek(0)
                    event_filedes.truncate()

                event_filedes.close()
                if file_was_empty:
                    # If the file was empty, this considers that maybe the underlying entity
                    # does not change anymore, or is destroyed. Then is deletes the file.
                    # If new data is written for this entity, the file will be recreated anyway.
                    # Another possibility to to check the last modification time with fileno(),
                    # os.fstat() and the member st_mtime, then delete it if too old.
                    try:
                        # Maybe the file is accessed at the same time, this is not a problem.
                        os.remove(event_filename)
                    except:
                        pass
            break
        except Exception as exc:
            sys.stderr.write("_get_events_from_file failed event_filename=%s exc=%s\n" % (event_filename, exc))
            # File locked or does not exist.
            time.sleep(sleep_delay)
            sleep_delay *= 2

    # sys.stderr.write("_get_events_from_file num triples=%d\n" % len(triples_list))
    return triples_list


def retrieve_events_by_entity(entity_type, entity_attributes):
    DEBUG("retrieve_events_by_entity entity_type=%s",entity_type)
    assert isinstance(entity_attributes, dict )

    # Only the useful properties are filtered, and stored in the ontology order.
    # This will break if one attribute is missing.
    events_filepath = _moniker_to_event_filename((entity_type, entity_attributes))

    events_triples_list = _get_events_from_file(events_filepath)

    DEBUG("retrieve_events_by_entity triples number=%d",len(events_triples_list))
    return events_triples_list


# TODO: The same event might appear in two objects.
def retrieve_all_events():
    DEBUG("retrieve_all_events events_directory=%s", events_directory)

    triples_list = []
    for dirpath, dnames, fnames in os.walk(events_directory):
        for events_filename in fnames:
            #sys.stderr.write("retrieve_all_events filNam=%s\n"%filNam)
            if events_filename.endswith(events_file_extension):
                events_pathname = dirpath + "/" + events_filename
                sys.stderr.write("retrieve_all_events events_pathname=%s\n" % events_pathname)
                triples_sublist = _get_events_from_file(events_pathname)
                triples_list.extend(triples_sublist)
    DEBUG("retrieve_all_events leaving with %d triples." % len(triples_list))
    return triples_list


# This stores a list of triples in json format, into a RDF file descriptor or stream.
def json_triples_to_rdf(json_triples, rdf_file_path):
    rdflib_graph = lib_kbase.MakeGraph()
    for tripl in json_triples:
        rdf_triple = _triple_json_to_rdf(tripl)
        rdflib_graph.add(rdf_triple)
    rdflib_graph.serialize(destination = rdf_file_path, format='pretty-xml')
