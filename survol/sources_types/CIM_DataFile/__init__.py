"""
Standard data file.
"""

import os
import sys
import datetime
import logging
import json

import lib_common
import lib_util
import lib_uris
import lib_properties
from lib_properties import pc
import lib_mime


def EntityOntology():
    return (["Name"],)


def EntityName(entity_ids_arr):
    entity_id = entity_ids_arr[0]
    # A file name can be very long, so it is truncated.
    file_basename = os.path.basename(entity_id)
    if file_basename == "":
        return entity_id
    else:
        return file_basename


def AddMagic(grph, file_node, file_name):
    try:
        import magic
    except ImportError:
        logging.debug("File magic unavailable:%s", file_name)
        return

    try:
        ms = magic.open(magic.MAGIC_NONE)
        ms.load()
        mtype = ms.file(file_name)
        ms.close()
        grph.add((file_node, pc.property_information, lib_util.NodeLiteral(mtype)))
    except TypeError:
        logging.debug("Type error:%s", file_name)
        return


def _int_to_date_literal(time_stamp):
    """Transforms a "stat" date into something which can be printed."""
    dt_str = datetime.datetime.fromtimestamp(time_stamp).strftime('%Y-%m-%d %H:%M:%S')
    return lib_util.NodeLiteral(dt_str)


def AddStatNode(grph, file_node, info_stat):
    """Adds to the node of a file some information taken from a call to stat()."""

    # st_size: size of file, in bytes. The SI unit is mentioned.
    siz_unit = lib_util.AddSIUnit(info_stat.st_size, "B")
    grph.add((file_node, pc.property_file_size, lib_util.NodeLiteral(siz_unit)))

    grph.add((file_node, pc.property_last_access, _int_to_date_literal(info_stat.st_atime)))
    grph.add((file_node, pc.property_last_change, _int_to_date_literal(info_stat.st_mtime)))
    grph.add((file_node, pc.property_last_metadata_change, _int_to_date_literal(info_stat.st_ctime)))


def AddStat(grph, file_node, file_name):
    try:
        stat_obj = os.stat(file_name)
    except Exception as exc:
        # If there is an error, displays the message.
        # AddStat:[Error 2] The system cannot find the file specified: 'abc %2C def %2C jhi %28 klm %29 nop'
        msg = "AddStat:" + str(exc)
        logging.error("Error os.stat file_name=%s" % file_name)
        grph.add((file_node, pc.property_information, lib_util.NodeLiteral(msg)))
        return
    AddStatNode(grph, file_node, stat_obj)


# BEWARE: This link always as a literal. So it is simpler to display in an embedded HTML table.
def AddHtml(grph, file_node, file_name):
    """Get the mime type, maybe with Magic. Then return a URL with for this mime type.
    This is a separated script because it returns HTML data, not RDF."""

    mime_stuff = lib_mime.filename_to_mime(file_name)
    mime_type = mime_stuff[0]

    if mime_type:
        lib_mime.AddMimeUrl(grph, file_node, "CIM_DataFile", mime_type, [file_name])


def _add_parent_dir(grph, file_node, file_name):
    """Display the node of the directory this file is in."""
    dir_path = os.path.dirname(file_name)
    if dir_path and dir_path != file_name:
        # Possibly trunc last backslash such as in "C:\" as it crashes graphviz !
        if dir_path[-1] == "\\":
            dir_path = dir_path[:-1]
        dir_node = lib_uris.gUriGen.DirectoryUri(dir_path)
        # We do not use the property pc.property_directory because it breaks the display.
        # Also, the direction is inverted so the current file is displayed on the left.
        grph.add((file_node, lib_common.MakeProp("Top directory"), dir_node))


# Plain call to stat with some filtering if the file does not exists.
def GetInfoStat(file_name):
    try:
        info = os.stat(file_name)
    except Exception as exc:
        # On recent Python versions, we would catch IOError or FileNotFoundError.
        lib_common.ErrorMessageHtml("Caught:" + str(exc))
    except IOError:
        lib_common.ErrorMessageHtml("IOError:" + file_name)
    except FileNotFoundError:
        lib_common.ErrorMessageHtml("File not found:" + file_name)
    except PermissionError:
        lib_common.ErrorMessageHtml("Permission error:" + file_name)
    except OSError:
        lib_common.ErrorMessageHtml("Incorrect syntax:" + file_name)

    return info


def AddDevice(grph, file_node, info):
    device_name = "Device:"+str(info.st_dev)
    if lib_util.isPlatformLinux:
        # TODO: How to get the device name on Windows ???
        file_mounts = open('/proc/mounts')
        for line in file_mounts:
            # lines are device, mountpoint, filesystem, <rest>
            # later entries override earlier ones
            line_split_end = line.split()[:3]
            if lib_util.isPlatformLinux:
                line = [s for s in line_split_end]
            else:
                line = [s.decode('string_escape') for s in line_split_end]
            try:
                if os.lstat(line[1]).st_dev == info.st_dev:
                    device_name = line[1]
                    break
            except OSError as exc:
                # Beware, index 1, not 0:
                # "[Errno 13] Permission denied: '/run/user/42/gvfs'"
                # Better display the error message.
                device_name=str(exc)
                break
        file_mounts.close()

        device_node = lib_uris.gUriGen.DiskPartitionUri(device_name)
        grph.add((file_node, pc.property_file_device, device_node))


def AddFileProperties(grph, current_node, current_filename):
    try:
        import win32api
        import lib_win32

        prop_dict = lib_win32.getFileProperties(current_filename)
        for prp, val in prop_dict.items():
            val = prop_dict[prp]
            if val is None:
                continue

            if isinstance(val, dict):
                val = json.dumps(val)
                # TODO: Unicode error encoding=ascii
                # 169    251    A9    10101001    "Copyright"    &#169;    &copy;    Copyright sign
                # Might contain this: "LegalCopyright Copyright \u00a9 2010"
                val = val.replace("\\", "\\\\")
            grph.add((current_node, lib_common.MakeProp(prp), lib_util.NodeLiteral(val)))
    except ImportError:
        pass

    file_mime_type = lib_mime.filename_to_mime(current_filename)
    if file_mime_type:
        if file_mime_type[0]:
            grph.add((current_node, lib_common.MakeProp("Mime type"), lib_util.NodeLiteral(str(file_mime_type))))


def AffFileOwner(grph, file_node, file_name):

    def add_file_owner_windows():
        try:
            import win32api
            import win32con
            import win32security
        except ImportError:
            return 

        from sources_types import Win32_UserAccount
        from sources_types import Win32_Group

        def SID_CodeToName(typeSID):
            mapSIDList = {
                win32security.SidTypeUser: "User SID",
                win32security.SidTypeGroup: "Group SID",
                win32security.SidTypeDomain: "Domain SID",
                win32security.SidTypeAlias: "Alias SID",
                win32security.SidTypeWellKnownGroup: "Well-known group",
                win32security.SidTypeDeletedAccount: "Deleted account",
                win32security.SidTypeInvalid: "Invalid SID",
                win32security.SidTypeUnknown: "Unknown type SID",
                win32security.SidTypeComputer: "Computer SID",
                # win32security.SidTypeLabel: "Mandatory integrity label SID" # NOT DEFINED
            }

            try:
                return mapSIDList[typeSID]
            except:
                return "Unknown SID"

        try:
            sd = win32security.GetFileSecurity (file_name, win32security.OWNER_SECURITY_INFORMATION)
        except Exception as exc:
            msg = str(exc)
            grph.add((file_node, pc.property_owner, lib_util.NodeLiteral(msg)))
            return

        owner_sid = sd.GetSecurityDescriptorOwner ()
        account_name, domain_name, typeCode = win32security.LookupAccountSid(None, owner_sid)
        typ_nam = SID_CodeToName(typeCode)
        logging.debug("Domain=%s Name=%s Type=%s", domain_name, account_name, typ_nam)

        if typeCode == win32security.SidTypeUser:
            account_node = Win32_UserAccount.MakeUri(account_name, domain_name)
        elif typeCode == win32security.SidTypeGroup:
            account_node = Win32_Group.MakeUri(account_name, domain_name)
        elif typeCode == win32security.SidTypeWellKnownGroup:
            account_node = Win32_Group.MakeUri(account_name, domain_name)
        else:
            # What else can we do ?
            account_node = Win32_UserAccount.MakeUri(account_name, domain_name)

        # TODO: What can we do with the domain ?
        grph.add((account_node, lib_common.MakeProp("Domain"), lib_util.NodeLiteral(domain_name)))
        grph.add((account_node, lib_common.MakeProp("SID"), lib_util.NodeLiteral(typ_nam)))
        grph.add((file_node, pc.property_owner, account_node))


    def add_file_owner_linux():
        # Do it a second time, but this is very fast.
        info = GetInfoStat(file_name)

        # st_uid: user id of owner.
        try:
            # Can work on Unix only.
            import pwd
            user = pwd.getpwuid(info.st_uid)
            user_name = user[0]
            user_node = lib_uris.gUriGen.UserUri(user_name)
            grph.add((file_node, pc.property_owner, user_node))
        except ImportError:
            pass

        # st_gid: group id of owner.
        try:
            # Can work on Unix only.
            import grp
            group = grp.getgrgid( info.st_gid )
            group_name = group[0]
            group_node = lib_uris.gUriGen.GroupUri(group_name)
            grph.add((file_node, pc.property_group, group_node))
        except ImportError:
            pass

        return

    try:
        if lib_util.isPlatformWindows:
            add_file_owner_windows()
        elif lib_util.isPlatformLinux:
            add_file_owner_linux()
        else:
            logging.warning("unknown OS")
            pass
    except:
        raise
        pass


def AddInfo(grph, node, entity_ids_arr):
    """
        This creates a couple of nodes about a file.
    """
    file_name = entity_ids_arr[0]

    if not file_name: # Faster than comparing to an empty string.
        return

    # Cleanup the filename. This function is called without knowledge of the specific case,
    # therefore the cleanup can only be done in code related to this entity type.
    file_name = lib_util.standardized_file_path(file_name)
    AddMagic(grph, node, file_name)
    AddStat(grph, node, file_name)
    AddHtml(grph, node, file_name)
    _add_parent_dir(grph, node, file_name)


# It receives as CGI arguments, the entity type which is "HttpUrl_MimeDocument", and the filename.
# It must then return the content of the file, with the right MIME type,
def DisplayAsMime(grph,node, entity_ids_arr):
    file_name = entity_ids_arr[0]

    mime_stuff = lib_mime.filename_to_mime(file_name)

    logging.debug("DisplayAsMime fileName=%s MIME:%s", file_name, str(mime_stuff))

    mime_type = mime_stuff[0]

    # It could also be a binary stream.
    if mime_type == None:
        lib_common.ErrorMessageHtml("No mime type for %s" % file_name)

    # TODO: Find a solution for JSON files such as:
    # "No mime type for C:\Users\rchateau\AppData\Roaming\Mozilla\Firefox\Profiles\gciw4sok.default/dh-ldata.json"

    try:
        # TODO: Change this with WSGI.
        lib_util.CopyFile(mime_type, file_name)
    except Exception as exc:
        lib_common.ErrorMessageHtml("file_to_mime.py Reading fileName=%s, caught:%s" % (file_name, str(exc)))


# TODO: Some files in /proc filesystem, on Linux, could be displayed
# not simply as plain text files, but with links replacing text.
# Example:
#
#  /proc/diskstats
#  11       0 sr0 0 0 0 0 0 0 0 0 0 0 0
#   8       0 sda 153201 6874 4387154 1139921 637311 564765 40773896 13580495 0 2700146 14726473
#
# /proc/devices
#Character devices:
#  4 /dev/vc/0
#  4 tty
#
#  ... etc ...
