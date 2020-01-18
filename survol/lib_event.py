# Stores and retrieves data related to an entity.
import os
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

valid_filename_chars = ",=-_.() %s%s" % (string.ascii_letters, string.digits)

# This transforms a string into a valid filename.
def StringToFileName(orgFilNam):
    #sys.stderr.write("StringToFileName orgFilNam=%s\n"%(orgFilNam))
    filNa = orgFilNam
    # replace spaces
    for r in '/\\ ':
        filNa = filNa.replace(r,'_')

    # keep only valid ascii chars
    # "must be unicode, not str"
    # cleaned_filename = unicodedata.normalize('NFKD', filNa).encode('ASCII', 'ignore').decode()
    cleaned_filename = filNa

    # keep only whitelisted chars
    retfilnam = ''.join(c for c in cleaned_filename if c in valid_filename_chars)
    #sys.stderr.write("StringToFileName retfilnam=%s\n"%(retfilnam))
    return retfilnam

# This assumes that the properties are in the order of the ontology.
def EntityTypeIdsToEventFile(entity_type,entity_ids_dict):
    dirEntity = events_directory + entity_type
    if not os.path.isdir(dirEntity):
        os.mkdir(dirEntity)

    #sys.stderr.write("EntityTypeIdsToEventFile entity_type=%s\n"%entity_type)

    # Build a file name; where the event will be stored.

    # These are the properties which uniquely define the object.
    eventFilNam = entity_type
    delim = "."
    for ontoAttrNam in entity_ids_dict:
        attrVal = entity_ids_dict[ontoAttrNam]
        encodeVal = attrVal
        eventFilNam += delim + ontoAttrNam + "=" + str(encodeVal)
        delim = ","

    #sys.stderr.write("EntityTypeIdsToEventFile eventFilNam=%s\n"%eventFilNam)

    # Because of Windows
    if len(eventFilNam) > 240:
        eventFilNam = eventFilNam[:240]

    # TODO: This is a temporary solution which should check the unicity of filenames
    # by adding a hash value at the end.

    eventFilNamLong = StringToFileName(eventFilNam) + events_file_extension

    #sys.stderr.write("EntityTypeIdsToEventFile eventFilNamLong=%s\n"%eventFilNamLong)

    return eventFilNamLong

# There is one directory per entity type.
# Then, each entity has its own file whose name is the rest of the moniker.
def MonikerToEventFile(jsonMonik):
    # The subject could be parsed with the usual functions made for moniker.
    entity_type = jsonMonik["entity_type"]
    #sys.stderr.write("MonikerToEventFile entity_type=%s\n"%entity_type)

    dirEntity = lib_common.tmpDir + "/Events/" + entity_type
    if not os.path.isdir(dirEntity):
        os.makedirs(dirEntity)

    #sys.stderr.write("MonikerToEventFile dirEntity=%s\n"%dirEntity)
    arrOnto = lib_util.OntologyClassKeys(entity_type)

    #sys.stderr.write("MonikerToEventFile arrOnto=%s\n"%str(arrOnto))
    entity_ids_dict = {}

    # Only the properties we need.
    for ontoAttrNam in arrOnto:
        attrVal = jsonMonik[ontoAttrNam]
        entity_ids_dict[ ontoAttrNam ] = attrVal

    eventFilNam = EntityTypeIdsToEventFile(entity_type,entity_ids_dict)

    #sys.stderr.write("MonikerToEventFile eventFilNam=%s\n"%eventFilNam)
    eventPath = dirEntity + "/" + eventFilNam
    return eventPath

def AddEventToObject(theObject,jsonData):
    eventFilNam = MonikerToEventFile(theObject)
    # sys.stderr.write("AddEventToObject eventFilNam=%s jsonData=%s\n"%(eventFilNam,str(jsonData)))
    # One JSON triple per line.

    # Try several times in case the script event_get.py would read at the same time.
    maxTry = 3
    sleep_delay = 0.1
    while maxTry > 0:
        maxTry -= 1
        try:
            # Appends a new event at the end.
            eventFd = open(eventFilNam,"a")
            # This must be as fast as possible, so event_get is not blocked..
            json.dump(jsonData, eventFd)
            eventFd.write("\n")
            eventFd.close()
            #sys.stderr.write("AddEventToObject closing file\n")

            break
        except Exception as exc:
            #sys.stderr.write("AddEventToObject waiting:%s\n"%str(exc))
            time.sleep(sleep_delay)
            sleep_delay *= 2
    if maxTry == 0:
        WARNING("AddEventToObject leaving. Failed.")


# This receives a json which has this structure:
# subject: A CIM object.
# predicate: A string.
# object: A literal or a CIM object.
# This is in reality a RDF triple, but it is not needed to import
# the rdflib module.
# Also, this relies on json to move the strings,
# so there is no coding issue.
# Also: It is not needed yet to load the ontology in the client.
def data_store(json_data):
    # TODO: Receive an array.
    # sys.stderr.write("data_store entering.\n")
    # The subject is always there and telles where the data are stored.
    valSubject = json_data["subject"]
    AddEventToObject(valSubject,json_data)
    #sys.stderr.write("data_store stored subject.\n")

    valObject = json_data["object"]

    # The object might be another CIM object or a literal.
    if isinstance(valObject,dict):
        AddEventToObject(valObject,json_data)
        #sys.stderr.write("data_store stored object.\n")

    #sys.stderr.write("data_store leaving.\n")

def data_store_list(json_data_list):
    DEBUG("data_store_list entering. Numtriples=%d.",len(json_data_list))
    for json_data in json_data_list:
        try:
            data_store(json_data)
        except Exception as exc:
            WARNING("data_store_list caught:%s. Json=%s",str(exc),str(json_data))
            traceback.print_exc()

    DEBUG("data_store_list leaving.")

def TripleJsonToRdf(jsonTriple):
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
    if isinstance(valObject,dict):
        txtObject = UrlJsonToTxt(valObject)
    else:
        txtObject = lib_kbase.MakeNodeLiteral(valObject)
        #sys.stderr.write("data_store stored object.\n")

    urlPred = lib_common.MakeProp(jsonTriple["predicate"])
    rdfTriple = (txtSubject,urlPred,txtObject)
    return rdfTriple


def get_data_from_file(eventFilNam):
    # sys.stderr.write("get_data_from_file eventFilNam=%s.\n"%eventFilNam)
    # Consider deleting the files if it is empty and not written to
    # for more than X hours, with os.fstat() and the member st_mtime

    # Try several times in case the script event_get.py would read at the same time.
    maxTry = 3
    sleep_delay = 0.1
    while maxTry > 0:
        maxTry -= 1
        try:
            #sys.stderr.write("get_data_from_file about to open eventFilNam=%s.\n"%eventFilNam)
            eventFd = open(eventFilNam,"r+")
            #sys.stderr.write("get_data_from_file opened eventFilNam=%s.\n"%eventFilNam)
            # This must be as fast as possible, so event_put is not blocked.
            for lineJson in eventFd.readlines():
                #sys.stderr.write("get_data_from_file lineJson=%s.\n"%lineJson)
                jsonTriple = json.loads(lineJson)
                # Now build Survol links which can be transformed in to valid RDF triples.
                rdfTriple = TripleJsonToRdf(jsonTriple)
                yield rdfTriple

            eventFd.seek(0)
            # TODO: BEWARE: WHY SHOULD WE DELETE OBJECTS IN THE GENERAL CASE ?
            # TODO: OR RATHER, THE INTERFACE SHOULD CHOOSE TO KEEP OBJECTS UNTIL THEY ARE EXPLICITLY DELETED ?
            eventFd.truncate()
            eventFd.close()
            break
        except:
            # File locked or does not exist.
            time.sleep(sleep_delay)
            sleep_delay *= 2

    if maxTry == 0:
        DEBUG("get_data_from_file eventFilNam=%s No data.",eventFilNam)

def data_retrieve(entity_type,entity_ids_arr):
    DEBUG("data_retrieve entity_type=%s",entity_type)

    arrOnto = lib_util.OntologyClassKeys(entity_type)

    # Properties are in the right order.
    entity_ids_dict = dict(zip(arrOnto, entity_ids_arr))

    eventFilNam = EntityTypeIdsToEventFile(entity_type,entity_ids_dict)

    DEBUG("data_retrieve eventFilNam=%s",eventFilNam)
    arrTriples = get_data_from_file(eventFilNam)

    DEBUG("data_retrieve NumTriples=%d",len(arrTriples))
    return arrTriples

# TODO: Events might appear in two objects.
def data_retrieve_all():
    DEBUG("data_retrieve_all events_directory=%s",events_directory)

    for dirpath, dnames, fnames in os.walk(events_directory):
        for filNam in fnames:
            #sys.stderr.write("data_retrieve_all filNam=%s\n"%filNam)
            if filNam.endswith(events_file_extension):
                pathNam = dirpath + "/" + filNam
                #sys.stderr.write("data_retrieve_all pathNam=%s\n"%pathNam)
                arrTriples = get_data_from_file(pathNam)
                for oneTripl in arrTriples:
                    yield oneTripl
    DEBUG("data_retrieve_all leaving")

def json_triples_to_rdf(json_triples, rdf_file_path):
    rdflib_graph = lib_kbase.MakeGraph()
    for tripl in json_triples:
        rdf_triple = TripleJsonToRdf(tripl)
        rdflib_graph.add(rdf_triple)
    rdflib_graph.serialize(destination = rdf_file_path, format='pretty-xml')

################################################################################

# Yields tuples of the form ( list(symbol), times), and repetition
# are detected over contiguous sequences of identical symbols.
# Symbols can be of any type except tuple and list.
def __squeeze_events_one(symbols_iterator):
    last_read_symbol = next(symbols_iterator)
    times_num = 1
    for one_symbol in symbols_iterator:
        if one_symbol == last_read_symbol:
            times_num += 1
        else:
            yield [last_read_symbol, ], times_num
            last_read_symbol = one_symbol
            times_num = 1
    yield [last_read_symbol, ], times_num


def __squeeze_events_multi_aux(symbols_iterator, max_len):
    if max_len == 1:
        symbols_iterator_next = __squeeze_events_one(symbols_iterator)
    else:
        iter_previous = __squeeze_events_multi_aux(symbols_iterator, max_len-1)
        symbols_iterator_next = __squeeze_events_fixed(iter_previous, max_len)
    for symbol_and_times in symbols_iterator_next:
        yield symbol_and_times


# Detects repetition of sub-sequences of up to max_len length.
def __squeeze_events_fixed(symbols_iterator, max_len):
    read_array_position = 0
    read_array_size = max_len * 2
    read_array = [None] * read_array_size
    for symbol_and_times in symbols_iterator:
        read_array[read_array_position] = symbol_and_times
        read_array_position += 1
        if read_array_position == read_array_size: break
    else:
        for sub_array_position in range(read_array_position):
            yield [read_array[sub_array_position], ], 1
        return

    times_num = 1
    while True:
        if read_array[:max_len] == read_array[max_len:]:
            sub_position = max_len
            times_num += 1
            for symbol_and_times in symbols_iterator:
                read_array[sub_position] = symbol_and_times
                sub_position += 1
                if sub_position == read_array_size: break
            else:
                yield read_array[:max_len], times_num
                for array_element in read_array[max_len: sub_position]:
                    yield [array_element, ], 1
                break
        elif times_num > 1:
            yield read_array[:max_len], times_num
            read_array[:max_len] = read_array[max_len:]
            times_num = 1
            sub_position = max_len
            for symbol_and_times in symbols_iterator:
                read_array[sub_position] = symbol_and_times
                sub_position += 1
                if sub_position == read_array_size: break
            else:
                for array_element in read_array[:sub_position]:
                    yield [array_element, ], 1
                break
        else:
            yield [read_array[0]], 1
            read_array[:-1] = read_array[1:]
            try:
                read_array[-1] = next(symbols_iterator)
            except StopIteration:
                for array_element in read_array[: -1]:
                    yield [array_element, ], 1
                break


def squeeze_events_sequence(input_events_sequence, max_len):
    symbols_iterator = iter(input_events_sequence)
    symbols_iterator_next = __squeeze_events_multi_aux(symbols_iterator, max_len)
    for symbol_and_times in symbols_iterator_next:
        yield symbol_and_times


def inflate_squeezed_sequence(list_output):
    # Not implemented yet.
    return list_output

