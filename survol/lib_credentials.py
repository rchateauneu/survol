import os
import sys
import json
import lib_util

# TODO: Several accesses per machine or database ?
# TODO: What if an access for "192.168.1.78" and "the_machine_name" ?


def credentials_filename():
    """This returns the file name containing the credentials.
    The filename can be overloaded with an environment variable."""
    credentials_basname = "SurvolCredentials.json"

    def _get_home_directory():
        if lib_util.isPlatformLinux:
            try:
                return os.environ["HOME"]
            except KeyError:
                return None
        else:
            try:
                home_drive = os.environ["HOMEDRIVE"]
            except:
                home_drive = "C:"
            try:
                # This is not defined on Travis.
                home_path = os.environ["HOMEPATH"]
                return os.path.join(home_drive, home_path)
            except KeyError:
                available_envs = os.environ.keys()
                sys.stderr.write("_get_home_directory: Available environment variables:%s\n" % str(available_envs))
                return None

    home_directory = _get_home_directory()
    if home_directory:
        cred_name = os.path.join(home_directory, credentials_basname).strip()
        if os.path.isfile(cred_name):
            return cred_name

    # The Travis tests do not store the credential file on the user's home directory
    # because this is not clearly defined, and anyway, it would potentially a security breach.
    cred_name = os.path.join(lib_util.gblTopScripts, "..", credentials_basname).strip()

    if os.path.isfile(cred_name):
        return cred_name

    raise Exception("credentials_filename: Cannot find a credentials filename:%s" % cred_name)


def _build_credentials_document():
    """This returns a map containing all credentials."""

    file_name = credentials_filename()

    try:
        with open(file_name) as cred_file:
            json_creds = json.load(cred_file)

        return json_creds
    except Exception as exc:
        WARNING("_build_credentials_document no credentials %s: %s", file_name, str(exc))
        return dict()


def _credentials_document():
    if not _credentials_document.credentials:
        _credentials_document.credentials = _build_credentials_document()

    return _credentials_document.credentials


_credentials_document.credentials = None


def GetCredentials(cred_type, cred_name):
    """For example: GetCredentials("Oracle","XE") or GetCredentials("Login","192.168.1.78")
    It returns the username and the password.
    """
    if cred_name is None:
        cred_name = ""
    credentials = _credentials_document()
    DEBUG("GetCredentials cred_type=%s cred_name=%s credentials=%d elements", cred_type, cred_name, len(credentials))
    try:
        if not credentials:
            return '', ''
        arr_type = credentials[cred_type]
    except KeyError:
        WARNING("GetCredentials Invalid type credType=%s credName=%s", cred_type, cred_name)
        return None, None

    # Try first without converting.
    try:
        cred = arr_type[cred_name]
        # sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
        return cred
    except KeyError:
        pass

    # We must convert the machine names to uppercase because this is "sometimes" done by Windows.
    # Might be a problem if several entries are identical except the case.
    key_val = credentials[cred_type]
    arr_type_upper = {subKey.upper(): key_val[subKey] for subKey in arr_type}

    cred_name_upper = cred_name.upper()
    try:
        cred = arr_type_upper[cred_name_upper]
        # sys.stderr.write("GetCredentials credType=%s credName=%s usr=%s pass=%s\n" % (credType,credName,cred[0],cred[1]))
        return cred
    except KeyError:
        WARNING("GetCredentials Unknown name credType=%s credName=%s", cred_type, cred_name)
        return '', ''


def get_credentials_names(cred_type):
    """For example, if "credType" == "Oracle", it will returned all databases defined in the credentials file."""

    # TODO: For Oracle, consider exploring tnsnames.ora ?
    try:
        cred_dict = _credentials_document()
        arr_type = cred_dict[cred_type]
        return arr_type.keys()
    except KeyError:
        ERROR("GetCredentials Invalid type credType=%s", cred_type)
        return []


def get_credentials_types():
    """Returns the various credential types taken form the confidential file: """
    try:
        cred_dict = _credentials_document()
        return cred_dict.keys()
    except KeyError:
        ERROR("GetCredentials Invalid document")
        return None


def _dump_credentials_to_file(cred_dict):
    """Mostly for debugging purpose."""
    fil_nam = credentials_filename()
    fil_fil = open(fil_nam, 'w')
    json.dump(cred_dict, fil_fil)
    fil_fil.close()


def add_one_credential(cred_type, cred_name, cred_usr, cred_pwd):
    cred_dict = _credentials_document()
    try:
        cred_dict[cred_type][cred_name] = [cred_usr, cred_pwd]
    except KeyError:
        try:
            cred_dict[cred_type] = {cred_name : [cred_usr, cred_pwd]}
        except KeyError:
            cred_dict = {cred_type: {cred_name : [cred_usr, cred_pwd]}}

    _dump_credentials_to_file(cred_dict)


def update_credentials(cred_map_out):
    cred_dict = dict()
    for cred_type in cred_map_out:
        cred_dict[cred_type] = dict()
        for cred_name in cred_map_out[cred_type]:
            cred = cred_map_out[cred_type][cred_name]
            cred_dict[cred_type][cred_name] = [cred[0], cred[1]]
    _dump_credentials_to_file(cred_dict)


def key_url_cgi_encode(a_key_url):
    return a_key_url.replace("http://", "http:%2F%2F").replace("https://", "https:%2F%2F")
