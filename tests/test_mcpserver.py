#!/usr/bin/env python

"""Test the MCP server.
"""

from __future__ import print_function

__author__      = "Remi Chateauneu"
__copyright__   = "Copyright 2020-2026, Primhill Computers"
__license__ = "GPL"

import re
import sys
import time
import subprocess
import threading
import json
from pathlib import Path

import anyio
import pytest
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
import pprint
import rdflib

# { "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": { "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": { "name": "test", "version": "1.0"  } } }
# { "jsonrpc": "2.0",  "id": "unique-id-123",  "method": "tools/list",  "params": {} }

server_path = Path(__file__).parent.parent / "survol" / "scripts" / "mcpserver.py"

# Does not always work.
@pytest.mark.anyio
async def test_mcp_server_start_and_stop():

    print("\nTEST: before stdio_client", flush=True)

    server_params = StdioServerParameters(
        command=sys.executable,
        args=[str(server_path)],
    )

    async with stdio_client(
        server_params,
        errlog=sys.stderr) as (read, write):

        print("TEST: server process started", flush=True)

        async with ClientSession(read, write) as session:
            print("TEST: ClientSession created", flush=True)

            with anyio.fail_after(15):
                await session.initialize()

            print("TEST: initialize completed", flush=True)

    print("TEST: test_mcp_server_start_and_stop server stopped", flush=True)


# Synchronous test.
def helper_mcp_server_run_command_synchronous(requests_list):
    mcp_pipes = subprocess.Popen(
        [sys.executable, "-u", str(server_path)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )

    # stderr pipe has a limited size. When it is full, the MCP server is blocked.
    # This thread continuously reads stderr content so the MCP server is not blocked.
    def drain_stderr(stream):
        # It also filters redundant messages like "... No module named 'azure'"
        no_module_pattern = re.compile(r".*No module named '([^']*)'.*")
        detected_modules = set()
        for line in stream:
            match = no_module_pattern.match(line)
            if match:
                module_name = match.group(1)
                if module_name not in detected_modules:
                    detected_modules.add(module_name)
                    print(f"SERVER STDERR: No module named '{module_name}' (filtered)", flush=True)
            else:
                print("SERVER STDERR:", line, flush=True, end="")

    stderr_thread = threading.Thread(
        target=drain_stderr,
        args=(mcp_pipes.stderr,),
        daemon=True,
    )
    stderr_thread.start()

    print("Sending initialize...")

    responses_list = []

    for request in requests_list:
        mcp_pipes.stdin.write(json.dumps(request) + "\n")
        mcp_pipes.stdin.flush()

        print("Waiting for response...")

        response = mcp_pipes.stdout.readline()
        print("Response:", response)
        responses_list.append(json.loads(response))

    print("Stopping server...")

    mcp_pipes.stdin.close()
    mcp_pipes.terminate()
    mcp_pipes.wait(timeout=5)

    print("Server stopped.")
    print("Joining thread.")
    stderr_thread.join()

    print("Tests OK")
    return responses_list


request_init = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {
            "name": "test",
            "version": "1.0",
        },
    },
}


def test_mcp_server_start_and_stop_synchronous():
    # {"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{"experimental":{},"prompts":{"listChanged":false},"resources":{"subscribe":false,"listChanged":false},"tools":{"listChanged":false}},"serverInfo":{"name":"RDF system","version":"1.29.0"}}}
    responses = helper_mcp_server_run_command_synchronous([request_init])
    assert len(responses) == 1
    assert responses[0]["jsonrpc"] == "2.0"


def test_mcp_server_synchronous_tools():
    request_tools = { "jsonrpc": "2.0",  "id": "unique-id-123",  "method": "tools/list",  "params": {} }

    responses = helper_mcp_server_run_command_synchronous([request_init, request_tools])
    assert len(responses) == 2
    assert responses[0]["jsonrpc"] == "2.0"

    assert responses[1]["jsonrpc"] == "2.0"
    tools_list = responses[1]["result"]["tools"]

    # {"name":"CIM_DataFile.file_stat","description":"File stat information\n\nThis returns general information about a non-directory data file.","inputSchema":{"properties":{},"title":"CIM_DataFile.file_statArguments","type":"object"}}
    file_stat_list = [tool for tool in tools_list if tool["name"] == "CIM_DataFile.file_stat"]
    assert len(file_stat_list) == 1
    assert file_stat_list[0]["description"].startswith("File stat information")

    print(file_stat_list)


def test_mcp_server_synchronous_file_stat():
    filename_example = __file__.replace("\\", "/")
    request_file_stat = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "CIM_DataFile.file_stat",
            "arguments": {
                "moniker": "CIM_DataFile.Name=" + filename_example
            }
        }
    }

    # De toute facon c'est nul car il devrait y avoir un argument.
    # Au lieu de:
    """
    {
        "name":"CIM_DataFile.file_stat",
        "description":"File stat information\n\nThis returns general information about a non-directory data file.",
        "inputSchema":{"properties":{},"title":"CIM_DataFile.file_statArguments","type":"object"}
    }
    """
    # Ca devrait etre:

    """
    {
        "name": "CIM_DataFile.file_stat",
        "description": "File stat information\n\nThis returns general information about a non-directory data file.",
        "inputSchema": {
            "properties": {
            "moniker": {
                "type": "string"
            }
            },
            "required": [
            "moniker"
            ],
            "title": "CIM_DataFile.file_statArguments",
            "type": "object"
        }
    }
    """


    # Response: {"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":"Error executing tool CIM_DataFile.file_stat: str expected, not int"}],"isError":true}}

    responses = helper_mcp_server_run_command_synchronous([request_init, request_file_stat])
    assert len(responses) == 2
    assert responses[0]["jsonrpc"] == "2.0"

    assert responses[1]["jsonrpc"] == "2.0"
    print(responses[1])

def test_mcp_server_synchronous_enumerate_user():
    request_file_stat = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "enumerate_user",
            "arguments": {
            }
        }
    }

    responses = helper_mcp_server_run_command_synchronous([request_init, request_file_stat])
    assert len(responses) == 2
    assert responses[0]["jsonrpc"] == "2.0"

    pprint.pprint(responses[1], compact=True)
    assert responses[1]["jsonrpc"] == "2.0"
    assert responses[1]["result"]["isError"] == False

    content_jsonld = responses[1]["result"]["content"][0]['text']
    rdf_graph = rdflib.Graph()
    rdf_graph.parse(data=content_jsonld, format="json-ld")
    print("Number of triples:%d" % len(rdf_graph))
    for s, p, o in rdf_graph.triples((None, None, None)):
        print("s=%s p=%s o=%s" % (s, p, o))

