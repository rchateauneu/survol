import os
import sys
import lib_common
from lib_properties import pc
from sources_types import CIM_DataFile
from sources_types import CIM_Directory


def _add_file_or_dir(grph, file_path):
    if os.path.isdir(file_path):
        node_path = lib_common.gUriGen.FileUri(file_path)
        CIM_DataFile.AddInfo(grph, node_path, [file_path])
    else:
        node_path = lib_common.gUriGen.DirectoryUri(file_path)
        CIM_Directory.AddInfo(grph, node_path, [file_path])
    return node_path



def recursive_symlink_analysis(grph, file_path):
    norm_path = os.path.normpath(file_path)
    path_split = norm_path.split(os.sep)
    accumulated_path = [os.sep]
    node_previous = None
    # The first element is empty because this is an absolute path.
    for one_dir in path_split[1:]:
        sys.stderr.write("one_dir=%s\n" % one_dir)
        accumulated_path.append(one_dir)
        sys.stderr.write("accumulated_path=%s\n" % accumulated_path)
        join_path = os.path.join(*accumulated_path)
        sys.stderr.write("join_path=%s\n" % join_path)
        node_join = _add_file_or_dir(grph, join_path)

        real_path = os.path.realpath(join_path)
        if join_path != real_path:
            node_real = _add_file_or_dir(grph, real_path)
            grph.add((node_real, pc.property_symlink, node_join))

        if node_previous:
            grph.add((node_previous, pc.property_directory, node_join))
        node_previous = node_join


