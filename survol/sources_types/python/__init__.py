"""
Python language concepts
"""

import os
import sys
import logging
import lib_uris
import lib_common

pyExtensions = {
    ".py" : "Python source",
    ".pyw": "Python Windows source",
    ".pyc": "Compiled Python",
    ".pyo": "Optimised compiled Python",
    ".pyd": "Python DLL"}


# A Python file is associated to the corresponding *.pyc etc...
# This adds a link to all files in the same directory which has the same name,
# if the extension is a Python one.
def AddAssociatedFiles(grph, node, fil_nam):
    logging.debug("AddAssociatedFiles %s", fil_nam)
    filename_no_ext, file_extension = os.path.splitext(fil_nam)

    for ext in pyExtensions:
        fil_assoc_nam = filename_no_ext + ext

        logging.debug("fil_assoc_nam=%s fil_nam=%s", fil_assoc_nam, fil_nam)
        # Do not add a link to itself. Beware: Not reliable on Linux because of case sensitivities.
        if fil_assoc_nam.lower() != fil_nam.lower():
            if os.path.isfile(fil_assoc_nam):
                logging.debug("Link fil_assoc_nam=%s filNam=%s", fil_assoc_nam, fil_nam)
                fil_assoc_node = lib_uris.gUriGen.FileUri(fil_assoc_nam)
                grph.add((node, lib_common.MakeProp(pyExtensions[ext]), fil_assoc_node))

