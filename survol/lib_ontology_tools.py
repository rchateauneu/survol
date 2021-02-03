import lib_util
import datetime
import json
import logging

################################################################################
def ManageLocalOntologyCache(ontology_name, ontology_extractor):
    """
    This caches data in files for performance.
    Extracting the entire ontology takes time.
    """
    tmp_dir = lib_util.get_temporary_directory()

    # A cache is valid for an entire month.
    # This cache is needed because WMI ontology extractors takes a lot of time.
    today_date = datetime.date.today()
    date_string = today_date.strftime("%Y%m")

    path_classes = "%s/ontology_classes.%s.%s.json" % (tmp_dir, ontology_name, date_string)
    path_attributes = "%s/ontology_attributes.%s.%s.json" % (tmp_dir, ontology_name, date_string)

    try:
        logging.info("ManageOntologyCache %s: Loading cached ontology from %s and %s",
             ontology_name, path_classes, path_attributes)
        fd_classes = open(path_classes)
        map_classes = json.load(fd_classes)
        fd_classes.close()

        fd_attributes = open(path_attributes)
        map_attributes = json.load(fd_attributes)
        fd_attributes.close()

        logging.info("ExtractWmiOntology %s: Loaded cached ontology from %s and %s",
             ontology_name, path_classes, path_attributes)
        return map_classes, map_attributes
    except Exception as exc:
        logging.info("ManageOntologyCache %s: Caught: %s. Creating cache file.", ontology_name, exc)

    map_classes, map_attributes = ontology_extractor()
    logging.info("ManageOntologyCache %s: Saving ontology to %s and %s",
        ontology_name, path_classes, path_attributes)

    fd_classes = open(path_classes, "w")
    json.dump(map_classes, fd_classes)
    fd_classes.close()

    fd_attributes = open(path_attributes, "w")
    json.dump(map_attributes, fd_attributes)
    fd_attributes.close()

    return map_classes, map_attributes

