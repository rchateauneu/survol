# TODO: This takes a bookmark file, and loads the content of urls.
# This is convenient for testing because successes and failures are counted.

import os
import sys
import signal


# This loads the module from the source, so no need to install it, and no need of virtualenv.
fil_root = ".."
if sys.path[0] != fil_root:
    sys.path.insert(0, fil_root)

import lib_bookmark

def _get_content(url_h_ref, time_out):
    if sys.version_info >= (3,):
        from urllib.request import urlopen
        f = urlopen(url_h_ref, None, time_out)
    else:
        from urllib2 import urlopen
        try:
            f = urlopen(url_h_ref, timeout=time_out)
        except:
            return None

    return f


################################################################################
counter_success = 0
counter_failure = 0
counter_timeout = 0

################################################################################
# This is set by a signal handler when a control-C is typed.
# It then triggers a clean exit, and creation of output results.
# This allows to monitor a running process, just for a given time
# without stopping it.
G_Interrupt = False

################################################################################


def _recursive_bookmarks_processing(a_dict, indent=0):
    global counter_success
    global counter_failure
    global counter_timeout

    if G_Interrupt:
        return False

    def truncate_value(value):
        value = value.strip()
        str_val = str(value)
        return str_val

    try:
        the_name = a_dict["name"]
    except KeyError:
        the_name = "No name"

    try:
        url_h_ref = str(a_dict["HREF"])
    except KeyError:
        # If no URL
        str_val = truncate_value(the_name)
        url_h_ref = None

    # Temporary filter because this URL does not work anymore.
    if url_h_ref and url_h_ref.find("ddns") >= 0:
        url_h_ref = None

    if url_h_ref:
        sys.stdout.write("URL:%s\n" % url_h_ref)
        try:
            f = _get_content(url_h_ref, time_out=10)
            if not f:
                print("TIMEOUT")
                counter_timeout += 1
            else:
                myfile = f.read()
                sys.stdout.write("Content: %d bytes\n" % len(myfile))
                counter_success += 1
        except IOError:
            counter_failure += 1

    for key_dict in sorted(a_dict.keys()):
        if key_dict not in ["children", "HREF", "name"]:
            val_dict = a_dict[key_dict]

    try:
        for one_obj in a_dict["children"]:
            resu = _recursive_bookmarks_processing(one_obj, indent + 1)
            if not resu:
                break
    except KeyError:
        pass

    return True


def signal_handler(signal, frame):
    print('You pressed Ctrl+C!')
    global G_Interrupt
    G_Interrupt = True



def Main():
    # When waiting for a process, interrupt with control-C.
    signal.signal(signal.SIGINT, signal_handler)
    print('Press Ctrl+C to exit cleanly')

    try:
        fil_nam = sys.argv[1]
    except:
        fil_nam = os.path.join(os.path.dirname(__file__), "..", "..",  "Docs", "bookmarks.html")

    # Google bookmark is another possible source of bookmarks.
    # urlNam = "https://www.google.com/bookmarks/bookmarks.html?hl=fr"

    dict_bookmarks = lib_bookmark.ImportBookmarkFile(fil_nam)

    _recursive_bookmarks_processing(dict_bookmarks)

    sys.stdout.write("Successes:%d\n" % counter_success)
    sys.stdout.write("Failures :%d\n" % counter_failure)
    sys.stdout.write("Time-outs:%d\n" % counter_timeout)


if __name__ == '__main__':
    Main()
