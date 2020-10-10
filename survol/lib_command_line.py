import os
import sys
import getopt


def command_line_to_cgi_args():
    """It is possible to run these scripts as CGI scripts.
    But is is also possible to run them as command line scripts
    http://thehost/survol/sources_types/TheClass/the_script.py?xid=TheClass.arg1=val1,arg2=val2
    becomes :
    python sources_types/TheClass/the_script.py val1 val2
    - The class and its ontology are known because of the directory.

    BEWARE: The mode cannot be changed because of GuessDisplayMode()
    """

    # If the script is running in CGI mode, then nothing to do.
    if "QUERY_STRING" in os.environ:
        return

    # PYTHONPATH is already set at the right value, otherwise we would not be here.

    # TODO: Ideally, this could reproduce Linux or Windows commands.

    # Possible values: "survol/entity.py", "survol/sources_types/enumerate_cgroup.py" or
    # "survol/sources_types/CIM_DataFile/file_stat.py"
    script_name = sys.argv[0]
    sys.stderr.write("script_name=%s\n" % script_name)
    split_script = os.path.split(script_name)
    class_name = None
    try:
        index_sources_types = split_script.index("sources_types")
        if index_sources_types < len(split_script) - 1:
            class_name = split_script[index_sources_types + 1]
    except:
        pass
    display_mode = "json"

    line_options, line_arguments = getopt.getopt(sys.argv[1:], "hc:m:", ["help", "class=", "mode="])
    for an_opt, a_val in line_options:
        if an_opt in ("-c", "--class"):
            class_name = a_val
        elif an_opt in ("-m", "--mode"):
            display_mode = a_val
        elif an_opt in ("-h", "--help"):
            print(script_name)
            print("Bad parameters")
            sys.exit()
        else:
            assert False, "Unhandled option:%s" % an_opt

    query_string = script_name
    query_string += "?mode=%s" % display_mode
    if class_name:
        query_string += "&xid=%s." % class_name

        # Now the rest of arguments are key-value pairs.
        # TODO: The attributes could be deduced from the ontology of the class.

        entity_ids = ",".join(line_arguments)
        query_string += entity_ids

    sys.stderr.write("query_string=%s\n" % query_string)
    sys.exit(1)

    os.environ["QUERY_STRING"] = query_string
    os.environ["SCRIPT_NAME"] = script_name
    # os.environ["SERVER_NAME"] = script_name

    # TODO: Add profiling because this is much easier to profile from the command line than in a HTTP server.
    # See: python -m cProfile -s cumulative -m pytest tests/test_dockit.py::ReplaySessionsTest::test_replay_all_trace_files

    # At this stage, the rest of the script runs as if started by a HTTP server,
    # with a default output mode which is more appropriate for a command line tool.
    # This is very convenient for debugging.
    # TODO: If the script is an events generators, it should loop like "tail -f"

