#!/usr/bin/env python

"""
File names in process memory.
"""

import os
import sys
import re
import logging

import lib_uris
import lib_util
import lib_common
from lib_properties import pc

from sources_types import CIM_Process
from sources_types.CIM_Process import memory_regex_search

SlowScript = True


class FilenameParserLinux:
    # https://stackoverflow.com/questions/1976007/what-characters-are-forbidden-in-windows-and-linux-directory-names
    # This is a most plausible regular expressions.
    # Most file names do not contain UTF-8 characters, are not "too long" nor "too short".
    def create_regex(self, minimum_depth, withRelat):

        rgx_fil_nam = ""
        rgx_fil_nam += r"/[-a-zA-Z0-9\._\+]{3,50}" * minimum_depth
        return rgx_fil_nam

    def cleanup_filename(self, a_filename):
        return False, [a_filename.decode()]


class FilenameParserWindows:

    # Beware that slash-separated filenames are also legal in Windows.
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa365247(v=vs.85).aspx
    def create_regex(self, minimum_depth, withRelat):
        # This is the hard disk.
        rgx_fil_nam = "[^a-zA-Z][A-Z]:"

        # In Windows, the last character should not be a space or a dot.
        # There must be at least one character.
        one_regex_normal = r'[^\\/<>:"\|\*\?]+[^. ]'
        # Dot is allowed for current or parent directory
        one_regex_no_slash = "(" + one_regex_normal + r"|\.\.|\.)"
        one_regex = r"[/\\]" + one_regex_no_slash

        rgx_fil_nam += one_regex * minimum_depth
        rgx_fil_nam += one_regex

        return rgx_fil_nam

    def cleanup_filename(self, a_filename):
        # Truncate first character, because not in the regex.
        a_filename = a_filename[1:]

        # file() argument 1 must be encoded string without NULL bytes, not str
        idx_zero = a_filename.find(b'\0')
        if idx_zero >= 0:
            # logging.error("ZERO ZERO ZERO")
            a_filename = a_filename[:idx_zero]

        # Keep only allowed chars in a filename.
        # TODO: This is not reliable and cannot be, because:
        # TODO: - The process is not suspended.
        # TODO: - The entire memory is scanned, including temporary variables etc...
        # TODO: The aim is only to give a hint of files possibly accessed.
        a_filename = re.sub(br"[^-_= \t/\\:@.#%$\"'!?a-zA-Z0-9]", b"", a_filename)

        # FIXME: There might be several filenames if it is a path.

        # "cp1252.pyt fleche en haut Non-ASCII character '\xe2'"

        # Could use os.path.pathsep but it needs a byte.
        if b';' in a_filename:
            # Maybe this is a PATH. Then split on ";". PATHs are treated differently
            # because their presence do not imply a actual directory access.
            return True, a_filename.decode().split(';')
        return False, [a_filename.decode()]


def _filename_parser_generator():
    if lib_util.isPlatformLinux:
        return FilenameParserLinux()
    if lib_util.isPlatformWindows:
        return FilenameParserWindows()
    lib_common.ErrorMessageHtml("No operating system")


def _check_unique_filenames(a_fil_nam, unique_filenames, param_check_existence):
    if a_fil_nam in unique_filenames:
        return

    #logging.warning("cleanup_filename a_fil_nam=%s", a_fil_nam)

    # The file must exist. If we cannot access it does not matter.
    # TODO: Must accept if we can access it or not.
    if param_check_existence:

        # TODO: Test existence of relative files by prefixing with current directory.
        if not os.path.isdir(a_fil_nam) and not os.path.isfile(a_fil_nam):
            logging.warning("File DOES NOT EXIST: %s" % a_fil_nam)
            pass
        else:
            unique_filenames.add(a_fil_nam)

    unique_filenames.add(a_fil_nam)


def Main():
    # Parameter for the minimal depth of the regular expression.
    # min=3, otherwise any string with a "/" will match.
    key_mini_depth = "Minimum filename depth"

    # Otherwise, only look for absolute filenames.
    key_with_relative = "Search relative filenames"

    key_check_existence = "Check file existence"

    cgiEnv = lib_common.ScriptEnvironment(
        parameters={key_mini_depth: 3, key_with_relative: False, key_check_existence: True})

    pid_as_integer = int(cgiEnv.GetId())

    param_mini_depth = int(cgiEnv.get_parameters(key_mini_depth))
    param_with_relative = bool(cgiEnv.get_parameters(key_with_relative))
    param_check_existence = bool(cgiEnv.get_parameters(key_check_existence))

    grph = cgiEnv.GetGraph()

    node_process = lib_uris.gUriGen.PidUri(pid_as_integer)

    try:
        obj_parser = _filename_parser_generator()
        rgx_fil_nam = obj_parser.create_regex(param_mini_depth, param_with_relative)
        logging.warning("rgx_fil_nam=%s", rgx_fil_nam)

        resu_fil_nams = memory_regex_search.GetRegexMatches(pid_as_integer, rgx_fil_nam)

        # This avoids duplicates.
        unique_filenames = set()

        # The file names which are detected in the process memory might be broken, invalid etc...
        # Only some of them are in valid strings. The other may come from deallocated memory etc...
        for idx_fil_nam in resu_fil_nams:
            a_fil_nam_buffer = resu_fil_nams[idx_fil_nam]
            if lib_util.is_py3:
                assert isinstance(a_fil_nam_buffer, bytes)
            else:
                assert isinstance(a_fil_nam_buffer, str)
            is_path, a_fil_nam_list = obj_parser.cleanup_filename(a_fil_nam_buffer)

            if is_path:
                # This is just a list of directories. This could be an interesting information,
                # but it does not imply the creation or access of actual files and cirectories.
                #logging.warning("THIS IS JUST A PATH:%s", str(a_fil_nam_list))
                pass
            else:
                # These files might actuqally be used.
                for one_filename in a_fil_nam_list:
                    #logging.error("ADDING %s", one_filename)
                    if lib_util.is_py3:
                        assert isinstance(one_filename, str)
                    else:
                        assert isinstance(one_filename, unicode)
                    _check_unique_filenames(one_filename, unique_filenames, param_check_existence)

        for a_fil_nam in unique_filenames:
            #logging.debug("a_fil_nam=%s",a_fil_nam)
            node_filnam = lib_uris.gUriGen.FileUri(a_fil_nam)
            grph.add((node_process, pc.property_rdf_data_nolist1, node_filnam))

        logging.warning("unique file numbers=%d", len(unique_filenames))

    except Exception as exc:
        lib_common.ErrorMessageHtml("Error:%s. Protection ?" % str(exc))

    cgiEnv.OutCgiRdf()


if __name__ == '__main__':
    Main()

