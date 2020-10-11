import os
import lib_common
from lib_properties import pc
from sources_types import CIM_DataFile
from sources_types import CIM_Directory


def _add_file_or_dir(grph, file_path):
    if os.path.isdir():
        node_path = lib_common.gUriGen.FileUri(file_path)
        CIM_DataFile.AddInfo(grph, node_path, [file_path])
    else:
        node_path = lib_common.gUriGen.DirectoryUri(file_path)
        CIM_Directory.AddInfo(grph, node_path, [file_path])
    return node_path


def recursive_symlink_analysis(grph, file_split, start_index = 1):
    if start_index == len(file_split):
        _add_file_or_dir(grph, os.path.join(file_split))
        return

    for index in range(start_index, len(file_split)):
        intermediary_split = file_split[:index]
        intermediary_path = os.path.join(intermediary_split)
        if os.path.islink(intermediary_path):
            real_intermediary = os.path.realpath(intermediary_path)
            node_real = _add_file_or_dir(grph, real_intermediary)
            node_link = _add_file_or_dir(grph, intermediary_path)
            grph.add((node_real, pc.property_symlink, node_link))

            recursive_symlink_analysis(grph, intermediary_split + real_intermediary, start_index + 1)
        recursive_symlink_analysis(grph, file_split, start_index + 1)


