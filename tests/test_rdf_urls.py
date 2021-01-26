#!/usr/bin/env python

"""Test of various URL, the content is checked in RDF.
It could be done in another output format. The goal is to maximize the coverage."""

from __future__ import print_function

import os
import sys
import socket
import unittest
import rdflib
import io
import lib_util
import lib_properties
from lib_properties import pc

from init import *

_current_machine = socket.gethostname()

def _check_script_rdf(agent_url, script_suffix):
    """This runs a URL and returns the result as a rdflib graph"""
    full_url = agent_url + script_suffix
    if full_url.find("?") >= 0:
        full_url += "&mode=rdf"
    else:
        full_url += "?mode=rdf"
    print("full_url=", full_url)
    # Some scripts take a long time to run.
    rdf_url_response = portable_urlopen(full_url, timeout=30)
    rdf_content = rdf_url_response.read()  # Py3:bytes, Py2:str
    result_graph = rdflib.Graph().parse(data=rdf_content, format="application/rdf+xml")

    return result_graph


class RdfLocalAgentTest(unittest.TestCase):
    """
    Test parsing of the RDF output on a locally running agent.
    """

    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf0TestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_rdf_test_agent)

    def _check_script(self, script_suffix):
        return _check_script_rdf(self._agent_url, script_suffix)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_rdf_SMB_net_share(self):
        result_graph = self._check_script("/survol/sources_types/SMB/net_share.py?xid=.")
        self.assertTrue(len(result_graph) > 0)

        shares_set = set()
        for url_subject, url_predicate, url_object in result_graph.triples((None, pc.property_smbshare, None)):
            url_path, entity_type, entity_id_dict = lib_util.split_url_to_entity(url_object)
            shares_set.add(entity_id_dict['Id'])
        print("Shares=", shares_set)

        # Typical SMB shares which are found on many Windows machines:
        # smbshr.Id=//machine-name/IPC$
        # smbshr.Id=//machine-name/C$
        # smbshr.Id=//machine-name/Users
        # smbshr.Id=//machine-name/ADMIN$
        self.assertTrue( "//%s/IPC$" % lib_util.currentHostname in shares_set)
        self.assertTrue( "//%s/C$" % lib_util.currentHostname in shares_set)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_rdf_windows_resource_icons(self):
        # This file contains at least one icon.
        file_path = "C:/Windows/System32/notepad.exe"
        result_graph = self._check_script(
            "/survol/sources_types/CIM_DataFile/win_resource_icons.py?xid=CIM_DataFile.Name=%s"
            % file_path)
        print("result_graph=", result_graph)
        for s, p, o in result_graph:
            if p.find("label") < 0 and p.find("comment") < 0 and p.find("domain") < 0 and p.find("range") < 0:
                print(s, p, o)
                print("")

        icon_url = None
        icon_attributes = None
        resource_icons = []
        resource_property = lib_properties.MakeProp("win32/resource")
        resources_triples = result_graph.triples((None, rdflib.namespace.RDF.type, resource_property))
        for url_subject, url_predicate, url_object in resources_triples:
            url_path, entity_type, entity_id_dict = lib_util.split_url_to_entity(url_subject)
        print("Resource icons=", resource_icons)
        self.assertEqual(entity_type, "win32/resource")
        self.assertEqual(entity_id_dict, {u'GroupName': u'2', u'Name': u'C:/Windows/System32/notepad.exe'})

    @unittest.skipIf(not is_platform_windows, "Windows only")
    @unittest.skip("Not implemented yet")
    def test_rdf_file_msvc_vcxproj(self):
        result_graph = self._check_script("/survol/sources_types/CIM_DataFile/file_msvc_vcxproj.py?xid=.")
        self.assertTrue(len(result_graph) > 0)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    @unittest.skip("Not implemented yet")
    def test_rdf_file_msvc_sln(self):
        result_graph = self._check_script("/survol/sources_types/CIM_DataFile/file_msvc_sln.py?xid=.")
        self.assertTrue(len(result_graph) > 0)

    # Content of tests\SampleDirSymbolicLinks, used for testing symbolic links:
    #     physical_directory.dir
    #         physical_subfile.dat
    #     physical_file.dat
    #     symlink_to_physical_directory
    #     symlink_to_physical_file
    #     symlink_to_subphysical_file

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_rdf_file_symlinks(self):
        test_dir_path = os.path.join(
            os.path.dirname(__file__),
            "SampleDirSymbolicLinks",
            "symlink_to_physical_file")
        result_graph = self._check_script(
            "/survol/sources_types/CIM_DataFile/file_symlinks.py?xid=CIM_DataFile.Name=%s"
            % test_dir_path)
        print("Result=", len(result_graph))
        links = list(result_graph.triples((None, lib_properties.pc.property_symlink, None)))
        self.assertEqual(len(links), 1)
        url_subject, url_predicate, url_object = links[0]
        print("url_subject=", url_subject)
        subject_url_path, subject_entity_type, subject_entity_id_dict = lib_util.split_url_to_entity(url_subject)
        print("subject_entity_id_dict=", subject_entity_id_dict)

        print("url_object=", url_object)
        object_url_path, object_entity_type, object_entity_id_dict = lib_util.split_url_to_entity(url_object)
        print("object_entity_id_dict=", object_entity_id_dict)

        print("links=", links)

        print("subject_entity_id_dict['Name']=", subject_entity_id_dict['Name'])
        print("object_entity_id_dict['Name']=", object_entity_id_dict['Name'])

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_rdf_file_symlinks_subfile(self):
        test_dir_path = os.path.join(
            os.path.dirname(__file__),
            "SampleDirSymbolicLinks",
            "symlink_to_subphysical_file")
        result_graph = self._check_script(
            "/survol/sources_types/CIM_DataFile/file_symlinks.py?xid=CIM_DataFile.Name=%s"
            % test_dir_path)
        print("Result=", len(result_graph))
        for s, p, o in result_graph.triples((None, lib_properties.pc.property_symlink, None)):
            print("    ", s, o)

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_rdf_dir_symlinks(self):
        test_dir_path = os.path.join(
            os.path.dirname(__file__),
            "SampleDirSymbolicLinks",
            "symlink_to_physical_directory")
        result_graph = self._check_script(
            "/survol/sources_types/CIM_Directory/dir_symlinks.py?xid=CIM_Directory.Name=%s"
            % test_dir_path)
        print("Result=", len(result_graph))
        for s, p, o in result_graph.triples((None, lib_properties.pc.property_symlink, None)):
            print("    ", s, o)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_win_depends(self):
        """Check the resource icon independencies of notepad.exe"""
        file_path = "C:/Windows/System32/notepad.exe"
        win_depends_content = self._check_script(
            "/survol/sources_types/CIM_DataFile/win_depends.py?xid=CIM_DataFile.Name=%s"
            % file_path)

        print("win_depends_content=", win_depends_content)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_win32_ip_config(self):
        """Test ip_config.py"""
        ip_config_content = self._check_script(
            "/survol/sources_types/win32/ip_config.py")

        print("ip_config_content=", ip_config_content)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_enumerate_com_type_lib(self):
        """Test enumerate_com_type_lib_content.py"""
        enumerate_com_type_lib_content = self._check_script(
            "/survol/sources_types/win32/enumerate_com_type_lib.py")

        print("enumerate_com_type_lib_content=", enumerate_com_type_lib_content)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_win32_enumerate_top_level_windows(self):
        """Test enumerate_top_level_windows.py"""
        enumerate_top_level_windows_content = self._check_script(
            "/survol/sources_types/win32/enumerate_top_level_windows.py")

        print("enumerate_top_level_windows_content=", enumerate_top_level_windows_content)

    def test_java_properties(self):
        """Investigate Java files"""
        file_path = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SampleJavaFile.java")

        java_properties = self._check_script(
            "/survol/sources_types/CIM_DataFile/java_properties.py?xid=CIM_DataFile.Name=%s"
            % file_path)

        print("java_properties=", java_properties)

    def test_python_properties(self):
        """Investigate Python files"""
        file_path = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")
        python_properties = self._check_script(
            "/survol/sources_types/CIM_DataFile/python_properties.py?xid=CIM_DataFile.Name=%s"
            % file_path)

        print("python_properties=", python_properties)

    def test_python_file_dis(self):
        """Investigate Python files"""
        file_path = os.path.join(os.path.dirname(__file__), "SampleDirScripts", "SamplePythonFile.py")
        python_file_dis = self._check_script(
            "/survol/sources_types/CIM_DataFile/python_file_dis.py?xid=CIM_DataFile.Name=%s"
            % file_path)

        print("python_file_dis=", python_file_dis)

    # Surprisingly, it fails only in this case.
    # @unittest.skipIf(is_travis_machine() and not is_py3, "Not implemented yet")
    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_module_deps(self):
        """Linux modules dependencies"""

        # $ uname -r
        # 4.11.8-300.fc26.x86_64
        proc_version = subprocess.check_output(['uname', '-r'])
        print("proc_version=", proc_version)

        # Any module will be ok.
        file_path = "/lib/modules/%s/kernel/net/sunrpc/sunrpc.ko.xz" % proc_version

        # Otherwise it cannot work.
        self.assertTrue(os.path.isfile(file_path))
        module_deps = self._check_script(
            "/survol/sources_types/CIM_DataFile/module_deps.py?xid=CIM_DataFile.Name=%s"
            % file_path)

        print("module_deps=", module_deps)

    @unittest.skipIf(not is_platform_linux, "Linux only")
    def test_ldd_depends(self):
        """
        Dependencies of a Linux shared library

        This just tests if the script can be called.
        """

        # Any shared object is ok.
        file_path = "/usr/lib/libr_util.so"
        ldd_depends = self._check_script(
            "/survol/sources_types/CIM_DataFile/ldd_depends.py?xid=CIM_DataFile.Name=%s"
            % file_path)

        print("ldd_depends=", ldd_depends)

    @unittest.skipIf(is_platform_windows or is_travis_machine(), "Linux only but not on Travis yet")
    def test_elftools_parse_classes(self):
        """
        Classes in an ELF file

        This just tests if the script can be called.
        """

        # This does not work with all files. May throw with "Magic number do not match"
        file_path = "/usr/lib64/libebtc.so"
        elftools_parse_classes = self._check_script(
            "/survol/sources_types/CIM_DataFile/elftools_parse_classes.py?xid=CIM_DataFile.Name=%s"
            % file_path)

        print("elftools_parse_classes=", elftools_parse_classes)

    def _get_arbitrary_mmap(self):
        """
        This returns an arbitraru memory-mapped file which can be used for testing.
        """
        current_proc_obj = psutil.Process()
        all_maps = current_proc_obj.memory_maps()
        for one_map in all_maps:
            break
        return one_map.path

    @unittest.skipIf(is_platform_windows, "Linux only")
    def test_memmap_processes(self):
        """
        Processes connected to a memory map
        """
        file_path = self._get_arbitrary_mmap()
        memmap_processes = self._check_script(
            "/survol/sources_types/memmap/memmap_processes.py?xid=memmap.Name=%s"
            % file_path)

        print("memmap_processes=", memmap_processes)
        # TODO: Current process should be in this processes list.

    @unittest.skipIf(is_platform_windows, "Linux only")
    def test_memmap_to_file(self):
        """File associated to a memory map"""
        file_path = self._get_arbitrary_mmap()
        memmap_to_file = self._check_script(
            "/survol/sources_types/memmap/memmap_to_file.py?xid=memmap.Name=%s"
            % file_path)

        print("memmap_to_file=", memmap_to_file)
        # TODO: This file must be accessible because it is mapped to the current process.


@unittest.skipIf(not is_platform_windows, "Windows only")
class MimeWindowsResourceIconsTest(unittest.TestCase):
    """
    Test parsing of the MIME output on a locally running agent.
    """

    def setUp(self):
        self._remote_mime_test_agent, self._agent_url = start_cgiserver(RemoteMimeTestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_mime_test_agent)

    def _check_script(self, script_suffix):
        """This runs a URL and returns the result as a ????? graph"""
        full_url = self._agent_url + script_suffix
        print("full_url=", full_url)

        # Some scripts take a long time to run.
        mime_url_response = portable_urlopen(full_url, timeout=30)
        mime_content = mime_url_response.read()  # Py3:bytes, Py2:str
        return mime_content

    def test_entity_mime_notepad_icon_present(self):
        """Check the resource icon in notepad.exe"""
        file_path = "C:/Windows/System32/notepad.exe"
        mime_content = self._check_script(
            "/survol/entity_mime.py?xid=win32/resource.Name=%s,GroupName=2&mode=mime:image/bmp"
            % file_path)

        print("type(mime_content)=", type(mime_content))

    @unittest.skipIf(not pkgutil.find_loader('PIL'), "PIL is needed.")
    def test_entity_mime_notepad_icon_content(self):
        """Check the resource icon and its content in notepad.exe"""

        file_path = "C:/Windows/System32/notepad.exe"
        mime_content = self._check_script(
            "/survol/entity_mime.py?xid=win32/resource.Name=%s,GroupName=2&mode=mime:image/bmp"
            % file_path)

        print("type(mime_content)=", type(mime_content), " len(mime_content)=", len(mime_content))

        import PIL.Image

        # Test the image size: This icon is 256*256 pixels.
        file_image = io.BytesIO(mime_content)
        print("type(file_image)=", type(file_image), " dir(file_image)=", dir(file_image))
        with PIL.Image.open(file_image) as img:
            print("img.format=", img.format)
            print("img.mode=", img.mode)
            print("img.size=", img.size)
            self.assertEqual(img.format, "BMP")
            self.assertEqual(img.mode, "RGB")
            self.assertEqual(img.size, (256, 256))


@unittest.skipIf(not is_platform_windows, "Windows only")
class CIM_ComputerSystem_Win32Test(unittest.TestCase):
    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf0TestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_rdf_test_agent)

    def _check_script(self, script_suffix):
        return _check_script_rdf(self._agent_url, script_suffix)

    def test_win32_NetSessionEnum(self):
        """Test of win32_NetSessionEnum.py"""

        win32_NetSessionEnum_result = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/Win32/win32_NetSessionEnum.py?xid=CIM_ComputerSystem.Name=%s"
            % _current_machine)

        print("win32_NetSessionEnum_result=", win32_NetSessionEnum_result)

    def test_win32_NetShareEnum(self):
        """Test of win32_NetShareEnum.py"""

        win32_NetShareEnum_result = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/Win32/win32_NetShareEnum.py?xid=CIM_ComputerSystem.Name=%s"
            % _current_machine)

        print("win32_NetShareEnum_result=", win32_NetShareEnum_result)

    def test_win32_NetUserEnum(self):
        """Test of win32_NetUserEnum.py"""

        win32_NetUserEnum_result = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/Win32/win32_NetUserEnum.py?xid=CIM_ComputerSystem.Name=%s"
            % _current_machine)

        print("win32_NetUserEnum_result=", win32_NetUserEnum_result)

    def test_win32_domain_machines(self):
        """Test of win32_domain_machines.py"""

        win32_domain_machines_result = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/Win32/win32_domain_machines.py?xid=CIM_ComputerSystem.Name=%s"
            % _current_machine)

        print("win32_domain_machines_result=", win32_domain_machines_result)

    def test_win32_host_local_groups(self):
        """Test of win32_host_local_groups.py"""

        win32_host_local_groups_result = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/Win32/win32_host_local_groups.py?xid=CIM_ComputerSystem.Name=%s"
            % _current_machine)

        print("win32_host_local_groups_result=", win32_host_local_groups_result)

    def test_win32_hostname_services(self):
        """Test of win32_hostname_services.py"""

        win32_hostname_services_result = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/Win32/win32_hostname_services.py?xid=CIM_ComputerSystem.Name=%s"
            % _current_machine)

        print("win32_hostname_services_result=", win32_hostname_services_result)


class CIM_ComputerSystem_JavaTest(unittest.TestCase):
    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf0TestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_rdf_test_agent)

    def _check_script(self, script_suffix):
        return _check_script_rdf(self._agent_url, script_suffix)

    @unittest.skipIf(not pkgutil.find_loader('jpype'), "jpype must be installed.")
    def test_rmi_registry(self):
        """Test of rmi_registry.py"""

        rmi_registry_result = self._check_script(
            "/survol/sources_types/CIM_ComputerSystem/java/rmi_registry.py?xid=CIM_ComputerSystem.Name=%s"
            % _current_machine)

        print("rmi_registry_result=", rmi_registry_result)


class OntologiesTest(unittest.TestCase):
    def setUp(self):
        # If a Survol agent does not run on this machine with this port, this script starts a local one.
        self._remote_rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf0TestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_rdf_test_agent)

    def _check_script(self, script_suffix):
        return _check_script_rdf(self._agent_url, script_suffix)

    def test_ontology_survol(self):
        """Test of Survol_RDFS.py"""

        survol_ontology_result = self._check_script(
            "/survol/ontologies/Survol_RDFS.py")

        print("survol_ontology_result=", survol_ontology_result)

    @unittest.skipIf(not is_platform_windows, "Windows only")
    def test_ontology_wmi(self):
        """Test of WMI_RDFS.py"""

        wmi_ontology_result = self._check_script(
            "/survol/ontologies/WMI_RDFS.py")

        print("wmi_ontology_result=", wmi_ontology_result)

    @unittest.skipIf(not is_linux_wbem(), "No WBEM.")
    def test_ontology_wbem(self):
        """Test of WBEM_RDFS.py"""

        wbem_ontology_result = self._check_script(
            "/survol/ontologies/WBEM_RDFS.py")

        print("wbem_ontology_result=", wbem_ontology_result)


class NmapTest(unittest.TestCase):
    def setUp(self):
        self._remote_rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf0TestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_rdf_test_agent)

    def _check_script(self, script_suffix):
        return _check_script_rdf(self._agent_url, script_suffix)

    def test_nmap_broadcast_upnp_info(self):
        """Test of nmap_broadcast_upnp_info.py"""
        nmap_broadcast_upnp_info_result = self._check_script(
            "/survol/sources_types/nmap/nmap_broadcast_upnp_info.py")
        print("nmap_broadcast_upnp_info_result=", nmap_broadcast_upnp_info_result)

    def test_nmap_broadcast_ms_sql_discover(self):
        """Test of nmap_broadcast_ms_sql_discover.py"""
        nmap_broadcast_ms_sql_discover_result = self._check_script(
            "/survol/sources_types/nmap/nmap_broadcast_ms_sql_discover.py")
        print("nmap_broadcast_ms_sql_discover_result=", nmap_broadcast_ms_sql_discover_result)

    def test_nmap_ping_scan(self):
        """Test of nmap_ping_scan.py"""
        nmap_ping_scan_result = self._check_script(
            "/survol/sources_types/nmap/nmap_ping_scan.py")
        print("nmap_ping_scan_result=", nmap_ping_scan_result)

    def test_nmap_run(self):
        """Test of nmap_run.py"""
        nmap_run_result = self._check_script(
            "/survol/sources_types/nmap/nmap_run.py")
        print("nmap_run_result=", nmap_run_result)

    def test_nmap_broadcast_netbios_master_browser(self):
        """Test of nmap_broadcast_netbios_master_browser.py"""
        nmap_broadcast_netbios_master_browser_result = self._check_script(
            "/survol/sources_types/nmap/nmap_broadcast_netbios_master_browser.py")
        print("nmap_broadcast_netbios_master_browser_result=", nmap_broadcast_netbios_master_browser_result)

    def test_nmap_broadcast_upnp_info(self):
        """Test of nmap_broadcast_upnp_info.py"""
        nmap_broadcast_upnp_info_result = self._check_script(
            "/survol/sources_types/nmap/nmap_broadcast_upnp_info.py")
        print("nmap_broadcast_upnp_info_result=", nmap_broadcast_upnp_info_result)


@unittest.skipIf(not check_program_exists("doxygen"), "doxygen must be installed.")
class DOxygenTest(unittest.TestCase):
    def setUp(self):
        self._remote_rdf_test_agent, self._agent_url = start_cgiserver(RemoteRdf0TestServerPort)
        print("AgentUrl=", self._agent_url)

    def tearDown(self):
        stop_cgiserver(self._remote_rdf_test_agent)

    def _check_doxygen_script(self, script_suffix):
        return _check_script_rdf(self._agent_url, script_suffix)

    def test_doxygen_dir(self):
        """Test of doxygen_dir.py"""
        test_dir_path = os.path.join(
            os.path.dirname(__file__),
            "SampleDirScripts")
        doxygen_dir_result = self._check_doxygen_script(
            "/survol/sources_types/CIM_Directory/doxygen_dir.py?xid=CIM_Directory.Name=%s" % test_dir_path)
        print("doxygen_dir_result=", doxygen_dir_result)

    def test_doxygen_file(self):
        """Test of doxygen_file.py"""
        test_file_path = os.path.join(
            os.path.dirname(__file__),
            "SampleDirScripts",
            "SamplePythonFile.py")
        doxygen_file_result = self._check_doxygen_script(
            "/survol/sources_types/CIM_Datafile/doxygen_file.py?xid=CIM_Datafile.Name=%s" % test_file_path)
        print("doxygen_file_result=", doxygen_file_result)


if __name__ == '__main__':
    unittest.main()

