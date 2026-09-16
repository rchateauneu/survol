from pathlib import Path
import importlib.util
import inspect
import os
import sys
import logging
import io
import traceback
import argparse 
import cProfile
import pstats

import six
import rdflib
from mcp.server.fastmcp import FastMCP

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import lib_util
import lib_common

#mcp = FastMCP(
#    "RDF system",
#    host="127.0.0.1",
#    port=8765,
#)
#mcp.run(transport="streamable-http")

mcp = FastMCP("RDF system")

class OutputMachineMcp:
    """
    This models the output of the header and the content.
    See the class lib_util.OutputMachineCgi
    """
    def __init__(self):
        self.m_output = io.BytesIO()

    def __del__(self):
        """
        Close object and discard memory buffer.
        """
        self.m_output.close()

    def Content(self):
        """
        This is specific to this class and returns a bytes containing the result sent to the HTTP client.
        :return:
        """
        logging.debug("OutputMachineMcp.Content")
        str_value = self.m_output.getvalue()
        assert isinstance(str_value, six.binary_type)
        return str_value

    def HeaderWriter(self, mime_type, extraArgs= None):
        """
        extraArgs is an array of key-value tuples.
        """
        logging.debug("OutputMachineMcp.HeaderWriter")
        pass

    def OutStream(self):
        logging.debug("OutputMachineMcp.OutStream")
        return self.m_output


# ----------------------------------------------------------------------
# PythonScript
# ----------------------------------------------------------------------

class PythonScript:

    def __init__(self, filepath: str, arguments: dict):

        path = Path(filepath)
        self.path = path
        # PythonScript.__init__ path=D:\Developpement\Survol\survol\survol\sources_types\enumerate_CIM_LogicalDisk.py name=enumerate_CIM_LogicalDisk arguments={}

        dir_prefix = os.path.dirname(os.path.dirname(__file__))
        shortened_path = str(path)[len(dir_prefix):].replace("\\", "/")

        source_dir = os.path.join(dir_prefix, "sources_types")
        self.name = str(path)[len(source_dir) + 1:].replace("\\", ".").replace("/", ".")[:-3]

        # http://laptop-r89kg6v1:8000/survol/sources_types/enumerate_CIM_LogicalDisk.py?mode=rdf

        # FIXME: Design error : The argument should have been named "moniker", not "xid".
        # FIXME: So this is hardcoded, but it does not really matter because there is a single argument.
        if arguments:
            self.query_string_pattern = "xid={moniker}&mode=mpcjson"
        else:
            self.query_string_pattern = "mode=mpcjson"

        self.request_uri_pattern = "/survol" + shortened_path + "?" + self.query_string_pattern
        self.uri_pattern = "http://laptop-r89kg6v1:8000" + self.request_uri_pattern

        # script -> "QUERY_STRING"
        logging.debug("filepath=%s arguments=%s self.uri_pattern=%s" % (filepath, arguments, self.uri_pattern))

        # self.query_string_pattern = "xid={moniker}&mode=mpcjson"
        self.script_name = str(path)

        self.arguments = arguments

        # Import the script exactly once.
        self.module = self._load()

        if not hasattr(self.module, "Main"):
            raise RuntimeError(
                f"{path}: no Main() function"
            )

        self.main_entry_point = self.module.Main
        self.description = self.module.__doc__.strip()

    def _load(self):

        if False:
            print(f"PythonScript._load path={self.path} name={self.name}")

        spec = importlib.util.spec_from_file_location(
            self.name,
            self.path
        )

        if spec is None or spec.loader is None:
            raise RuntimeError(
                f"Cannot load {self.path}"
            )

        module = importlib.util.module_from_spec(spec)

        spec.loader.exec_module(module)

        return module

    def run(self, arguments: dict) -> rdflib.Graph:
        logging.info("PythonScript.run script_name=%s" % self.script_name)
        logging.info("PythonScript.run query_string_pattern=%s" % self.query_string_pattern)
        # arguments={'moniker': 'C:\\temp\\foo.txt'}
        logging.info("PythonScript.run arguments=%s" % arguments)

        try:
            logging.info("PythonScript.run In try block")
            # Reproduce the CGI environment expected by the existing scripts.

            # self.uri=http://laptop-r89kg6v1:8000/survol/sources_types/CIM_DataFile/file_stat.py?xid={moniker}&mode=mpcjson

            # Typical url: http://vps516494.ovh.net/Survol/survol/entity.py?xid=CIM_DataFile.Name=/usr/bin/_demangler.py
            #              http://vps516494.ovh.net/Survol/survol/sources_types/CIM_DataFile/file_stat.py?xid=CIM_DataFile.Name%3D%2Fusr%2Fbin%2F_demangler.py

            # This is ugly but does not matter for the moment.
            logging.info("self.request_uri_pattern=%s" % self.request_uri_pattern)
            if "moniker" in arguments:
                assert self.request_uri_pattern.find("{moniker}") > 0
                assert self.query_string_pattern.find("{moniker}") > 0
                request_uri = self.request_uri_pattern.replace("{moniker}", arguments["moniker"])
                query_string = self.query_string_pattern.replace("{moniker}", arguments["moniker"])
            else:
                assert self.request_uri_pattern.find("{moniker}") < 0
                assert self.query_string_pattern.find("{moniker}") < 0
                request_uri = self.request_uri_pattern
                query_string = self.query_string_pattern
            logging.info("request_uri=%s" % request_uri)
            logging.info("query_string=%s" % query_string)
            os.environ["REQUEST_URI"] = request_uri
            os.environ["QUERY_STRING"] = query_string
            # Not really used because this is a transport="stdio" server.
            # It must be changed if the MCP server. Same for REMOTE_ADDR.
            os.environ["SERVER_PORT"] = "12345"
            os.environ["REMOTE_ADDR"] = "1.2.3.4"
            os.environ["SERVER_SOFTWARE"] = "The Server Software"
            # script_name=D:\Developpement\Survol\survol\survol\sources_types\CIM_DataFile\file_stat.py
            # script.name=CIM_DataFile.file_stat
            os.environ["SCRIPT_NAME"] = self.script_name
            os.environ["SERVER_NAME"] = "TheServerName"
            # os.environ["PYTHONPATH"] = 12

            # Main() is called on the already imported module.
            logging.info("PythonScript.run Before  %s" % self.script_name)
            the_out_mach = OutputMachineMcp()
            lib_util.globalOutMach = the_out_mach
            self.main_entry_point()
            logging.info("PythonScript.run Before Content %s" % self.script_name)
            execution_content = lib_util.globalOutMach.Content()
            logging.info("PythonScript.run execution_content=%s" % execution_content)
        except Exception as exc:
            logging.error("PythonScript.run caught=%s" % exc)
            logging.error("Traceback:")
            logging.error(traceback.format_exc())
            return None

        return execution_content


# ----------------------------------------------------------------------
# Tool generation
# ----------------------------------------------------------------------

def make_tool(script: PythonScript):

    async def tool(**kwargs):
        graph_as_json_ld = script.run(kwargs)
        logging.debug("tool type(graph_as_json_ld)=%s" % type(graph_as_json_ld))
        if graph_as_json_ld is None:
            raise Exception("Null error")
        return graph_as_json_ld

    # FastMCP uses the function signature to construct the MCP input schema.
    parameters = []

    logging.debug("script.name=%s" % script.name)
    logging.debug("script.description=%s" % script.description)
    for name, python_type in script.arguments.items():
        parameters.append(
            inspect.Parameter(
                name,
                inspect.Parameter.KEYWORD_ONLY,
                annotation=python_type
            )
        )

    tool.__signature__ = inspect.Signature(
        parameters
    )

    tool.__name__ = script.name
    tool.__doc__ = script.description

    return tool


# ----------------------------------------------------------------------
# Resource generation
# ----------------------------------------------------------------------

def make_resource(script: PythonScript):

    if not script.uri_pattern:
        raise RuntimeError(
            f"{script.name}: resource has no URI"
        )

    argument_names = list(
        script.arguments.keys()
    )

    if len(argument_names) != 1:
        raise RuntimeError(
            f"{script.name}: this implementation expects "
            f"exactly one resource argument"
        )

    argument_name = argument_names[0]

    # Why do we need script.uri_pattern ?
    @mcp.resource(
        script.uri_pattern,
        name=script.name,
        description=script.description,
        mime_type="application/rdf+json",
    )
    def resource(moniker: str):

        graph_as_json_ld = script.run({
            argument_name: moniker
        })
        logging.debug("resource type(graph_as_json_ld)=%s" % type(graph_as_json_ld))
        return graph_as_json_ld

    return resource


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def build_flat_hierarchy_from_dir(sources_types_directory: str):

    # If there is an error, it will not exit but send an exception which can be handled.
    lib_common.enable_error_message(False)

    scripts_list = []
    for root_path, dirs, files in os.walk(sources_types_directory):
        if root_path.endswith("__pycache__"):
            continue
        logging.debug("os.path.abspath(root_path)=%s sources_types_directory=%s" % (os.path.abspath(root_path), sources_types_directory))
        if os.path.abspath(root_path) == sources_types_directory:
            arguments = {}
        else:
            arguments = {"moniker": str}
        for top_level_script in files:
            if top_level_script == "__init__.py":
                continue
            logging.info("Processing script: %s %s" % (root_path, top_level_script))
            if not top_level_script.endswith(".py"):
                continue
            if top_level_script in ["__init__.py"]:
                continue

            script_path = os.path.join(root_path, top_level_script)

            try:
                new_script = PythonScript(script_path, arguments)
            except Exception as exc:
                logging.error("Cannot load %s: %s", script_path, exc)
                continue
            logging.info("Processed script: %s" % top_level_script)
            scripts_list.append(new_script)
    return scripts_list


def initialize_mcp_server():

    top_scripts_directory = os.path.dirname(os.path.dirname(__file__))

    make_resource(PythonScript(os.path.join(top_scripts_directory, "entity.py"), {"moniker": str}))

    top_scripts_directory_sources = os.path.join(top_scripts_directory, "sources_types")

    all_scripts = build_flat_hierarchy_from_dir(top_scripts_directory_sources)
    logging.info("len(all_scripts)=%d" % len(all_scripts))

    # Register every script with MCP.
    for script in all_scripts:
        tool = make_tool(script)
        mcp.tool()(tool)
    logging.info("tools created")

########################################################################

class SyncFileHandler(logging.FileHandler):
    def emit(self, record):
        super().emit(record)
        #self.flush()
        os.fsync(self.stream.fileno())


def set_logging(log_level):
    error_file = os.path.join(os.path.dirname(__file__), "mcpserver.log")

    root = logging.getLogger()
    root.setLevel(log_level)

    formatter = logging.Formatter(
        "MCP_MESSAGES %(asctime)s %(levelname)s %(name)s: %(message)s"
    )

    file_handler = SyncFileHandler(error_file, encoding="utf-8", mode='w')
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    loggerA = logging.getLogger(__name__)
    loggerA.info("Logger initialised %s", error_file)


general_profiler = None

def signal_handler(sig, frame):
    global general_profiler
    if general_profiler:
        general_profiler.disable()
        general_profiler.dump_stats("wsgiserver.profile")
        pstats.Stats(general_profiler).sort_stats(pstats.SortKey.CUMULATIVE).print_stats(100)
    sys.exit(0)



if __name__ == "__main__":
    set_logging(logging.DEBUG)

    logging.info("Starting (info)")
    parser = argparse.ArgumentParser(
        prog='mcpserver',
        description='mcpserver for Survol',
        epilog='')
    parser.add_argument('-i', '--init_only', action='store_true')
    parser.add_argument('-P', '--profile', action='store_true')

    args = parser.parse_args()

    if args.profile:
            general_profiler = cProfile.Profile()
            general_profiler.enable()

    initialize_mcp_server()

    if args.init_only:
        logging.info("Leaving...")
        signal_handler(None, None)
        exit(0)

    logging.info("Before run")
    # The alternative is "streamable-http"
    print("Calling mcp.run()", file=sys.stderr, flush=True)
    print("Calling mcp.run() second line", file=sys.stderr, flush=True)

    mcp.run(transport="stdio")

