import lib_common
import datetime
import json


################################################################################
# This caches data in files for performance.
# Extracting the entire ontology takes time.
def ManageLocalOntologyCache(ontology_name, ontology_extractor):
    tmp_dir = lib_common.TmpDir()

    # A cache can hold an entire month.
    today_date = datetime.date.today()
    date_string = today_date.strftime("%Y%m")

    path_classes = "%s/ontology_classes.%s.%s.json" % (tmp_dir, ontology_name, date_string)
    path_attributes = "%s/ontology_attributes.%s.%s.json" % (tmp_dir, ontology_name, date_string)

    try:
        INFO("ManageOntologyCache %s: Loading cached ontology from %s and %s",
             ontology_name, path_classes, path_attributes)
        fd_classes = open(path_classes)
        map_classes = json.load(fd_classes)
        fd_classes.close()

        fd_attributes = open(path_attributes)
        map_attributes = json.load(fd_attributes)
        fd_attributes.close()

        INFO("ExtractWmiOntology %s: Loaded cached ontology from %s and %s",
             ontology_name, path_classes, path_attributes)
        return map_classes, map_attributes
    except Exception as exc:
        INFO("ManageOntologyCache %s: Caught: %s. Creating cache file.", ontology_name, exc)

    map_classes, map_attributes = ontology_extractor()
    INFO("ManageOntologyCache %s: Saving ontology to %s and %s",
        ontology_name, path_classes, path_attributes)

    fd_classes = open(path_classes, "w")
    json.dump(map_classes, fd_classes)
    fd_classes.close()

    fd_attributes = open(path_attributes, "w")
    json.dump(map_attributes, fd_attributes)
    fd_attributes.close()

    return map_classes, map_attributes

