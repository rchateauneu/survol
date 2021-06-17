# accdb file accessed with ODBC.
# This is a feature if CIM_DataFile extension is accdb or csv or any extension compatible with an ODBC driver.
# Conditional because ODBC and pyodbc must be there, and the ODBC driver must be available too.

# This can also be used if an ODBC connection string is detected in a process memory or anywhere.

# This must also handle a connection string.

from __future__ import print_function

import unittest
import sys
import re

import six

import lib_uris
import lib_client
from sources_types import odbc as survol_odbc

from init import *

try:
    import pyodbc
except ImportError as exc:
    # Some tests can be done even if pyodbc is not installed.
    pyodbc = None


class MatchesAggregationTest(unittest.TestCase):
    """
    This tests the function which aggregates small key-value paris of ODBC connecitons strings,
    detected in a text buffer with regular expressions.
    These key-value pairs come in a map with their offest in the text.
    They are sorted based on this offset then concatenated when they are consecutive.
    It is faster than having a single regular expression with a sequence of kv pairs joined with a "|" pipe.
    """
    # Things to test:
    # - From bytes.
    # - From UTF8, on one, two or four bytes.

    def test_aggregate_dsn_pieces(self):
        # These test data are pairs:
        # - The first element contains the input dict of offset => token,
        # - The second element is the expected output.
        test_data = [
            (
                {
                    0: b"a",
                    1: b"b",
                },
                {
                    0: b"ab",
                }
            ),
            (
                {
                    0: b"a",
                    100: b"b",
                },
                {
                    0: b"a",
                    100: b"b",
                }
            ),
            (
                {
                    0: b"a",
                    1: b"b",
                    2: b"c",
                    3: b"d",
                },
                {
                    0: b"abcd",
                }
            ),
            (
                {
                    0: b"a",
                    1: b"b",
                    102: b"c",
                    103: b"d",
                },
                {
                    0: b"ab",
                    102: b"cd",
                }
            ),
        ]

        for input_dict, expected_dict in test_data:
            actual_dict = survol_odbc.aggregate_dsn_pieces(input_dict)
            self.assertEqual(expected_dict, actual_dict)


# Many examples of connection strings here: https://www.connectionstrings.com/
# This list uses only the most common keywords found in ODBC connection strings.
connection_strings_light = [
    r'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=C:\AnyDir\AnyFile.tmp;',
    r'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=c:\txtFilesFolder\;',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=C:\Documents;',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=c:\myFolder\myExcel2007file.xlsx;',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=c:\myFolder\myBinaryExcel2007file.xlsb;',
]

# More examples with more keywords.
connection_strings_heavy = connection_strings_light + [
    r'Data Source=MyOracleDB;User Id=myUsername;Password=myPassword;Integrated Security=no;',
    r'Data Source=myOracleDB;User Id=myUsername;Password=myPassword;Min Pool Size=10;Connection Lifetime=120;Connection Timeout=60;Incr Pool Size=5;Decr Pool Size=2;',
    r'Data Source=myOracleDB;User Id=SYS;Password=SYS;DBA Privilege=SYSOPER;',
    r'Data Source=username/password@//myserver:1521/my.service.com;',
    r'Data Source=190.190.200.100,1433;Network Library=DBMSSOCN;Initial Catalog=myDataBase;User ID=myUsername;Password=myPassword;',
    r'Driver={Microsoft Text Driver (*.txt; *.csv)};Dbq=C:\AnyDir\odbc_sample.csv;Extensions=asc,csv,tab,txt;',
    r'Driver=MapR Drill ODBC Driver;ConnectionType=Direct;Host=192.168.222.160;Port=31010',
    r'Driver={SQL Server};Server=lmtest;Database=lmdb;Uid=sa;Pwd=pass',
    r'Driver={MySQL ODBC 3.51 driver};server=lmtest;database=lmdb;uid=mysqluser;pwd=pass;',
    r'DSN=DSN_Name;Server=lmtest;Uid=lmuser;Pwd=pass',
    r'DSN=myDsn;Uid=myUsername;Pwd=;',
    r'FILEDSN=c:\myDsnFile.dsn;Uid=myUsername;Pwd=;',
    r'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=C:\AnyDir\AnyFile.tmp;Extended Properties="text;HDR=Yes;FMT=Delimited";',
    r'Provider=OraOLEDB.Oracle;Data Source=localhost:1521/XE;Initial Catalog=myDataBase;User Id=myUsername;Password=myPassword;',
    # Not sure about this specific keywords.
    #r'Provider=OraOLEDB.Oracle;Data Source=MyOracleDB;User Id=myUsername;Password=myPassword;OLEDB.NET=True;SPPrmsLOB=False;NDatatype=False;SPPrmsLOB=False;',
    r'Provider=OraOLEDB.Oracle;Data Source=(DESCRIPTION=(CID=GTU_APP)(ADDRESS_LIST=(ADDRESS=(PROTOCOL=TCP)(HOST=myHost)(PORT=myPort)))(CONNECT_DATA=(SID=MyOracleSID)(SERVER=DEDICATED)));User Id=myUsername;Password=myPassword;',
    r'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=c:\txtFilesFolder\;Extended Properties="text;HDR=Yes;FMT=Delimited";',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=c:\myFolder\myExcel2007file.xlsx;Extended Properties="Excel 12.0 Xml;HDR=YES";',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=c:\myFolder\myBinaryExcel2007file.xlsb;Extended Properties="Excel 12.0;HDR=YES";',
    r'SERVER=(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=MyHost)(PORT=MyPort))(CONNECT_DATA=(SERVICE_NAME=MyOracleSID)));uid=myUsername;pwd=myPassword;',
    r'Server=(localdb)\v11.0;Integrated Security=true;AttachDbFileName=C:\MyFolder\MyData.mdf;',
    r'Server=.\SQLExpress;AttachDbFilename=|DataDirectory|mydbfile.mdf;Database=dbname;Trusted_Connection=Yes;',
    r'Server=np:\\.\pipe\LOCALDB#F365A78E\tsql\query;',
    r'Server=(localdb)\.\MyInstanceShare;Integrated Security=true;',
]

# Various text strings to be added before and after a connectino string which is then analysed
# with a resular expression.
noise_text = [
    " lksdj;laksjdf;lkajsdf",
    " 9087sdva98uvohj.134mn5.23m4 ",
    " -098_)( *76586 ",
    " nothing=something ",
    " ;==; ",
]


@unittest.skipIf(pyodbc is None, "pyodbc must be installed")
class DetectConnectionStringTest(unittest.TestCase):
    """
    This tests the detection of a ODBC connection string hidden in text.
    """

    # Things to test:
    # - From bytes.
    # - From UTF8, on one, two or four bytes.

    def _aux_test_from_python_bytes(self, text_display, the_odbc_regex, various_connections):
        """
        This tests the detection of a ODBC connection string hidden in text.
        It uses a big regular expression.
        There are two regular expressiosn to detect them, based on the ODBC connecitons strigns keywords:
        A light one with just a handfull of keywords, the most common ones.
        A heavy regex, with all known keywords: The detection is then much slower.
        :param text_display: A small text to display, for information..
        :param the_odbc_regex:  Regex.
        :param various_connections: A list of connection strings, which will be hidden in random text, the detect.
        :return:
        """
        print(text_display, "=", the_odbc_regex)
        compiled_regex = re.compile(the_odbc_regex.encode('utf-8'), re.IGNORECASE)

        def connect_str_to_token_set(connect_str):
            return set(tok.strip() for tok in connect_str.split(";") if tok.strip())

        for one_connect_str in various_connections:
            print("")
            print("one_connect_str=", one_connect_str)
            for one_prefix in noise_text:
                for one_suffix in noise_text:
                    full_line = one_prefix + one_connect_str + one_suffix
                    bytes_array = full_line.encode('utf-8')
                    self.assertTrue(isinstance(bytes_array, six.binary_type))

                    resu_matches = {}
                    for mtch in compiled_regex.finditer(bytes_array):
                        resu_matches[mtch.start()] = mtch.group()

                    for one_offset, one_match in resu_matches.items():
                        print("    ", one_match)
                        self.assertTrue(isinstance(one_match, six.binary_type))

                    aggregated_matches = survol_odbc.aggregate_dsn_pieces(resu_matches)
                    print("aggregated_matches=", aggregated_matches)
                    self.assertTrue(isinstance(aggregated_matches, dict))
                    self.assertEqual(len(aggregated_matches), 1)
                    first_key = next(iter(aggregated_matches))
                    first_dsn = aggregated_matches[first_key]
                    print("first_dsn=", first_dsn)
                    first_dsn_as_str = first_dsn.decode("utf-8")
                    # The order of tokens might be different. Also, the last ";" might be stripped.
                    split_dsn_expected = connect_str_to_token_set(one_connect_str)
                    split_dsn_actual = connect_str_to_token_set(first_dsn_as_str)
                    self.assertEqual(split_dsn_expected, split_dsn_actual)

    def test_from_python_light_bytes(self):
        self._aux_test_from_python_bytes("regex_odbc_light", survol_odbc.regex_odbc_light, connection_strings_light)

    def test_from_python_heavy_bytes(self):
        self._aux_test_from_python_bytes("regex_odbc_heavy", survol_odbc.regex_odbc_heavy, connection_strings_heavy)


_client_object_instances_from_script = lib_client.SourceLocal.get_object_instances_from_script


@unittest.skipIf(pyodbc is None, "pyodbc must be installed")
@unittest.skipIf(is_platform_linux, "Windows test only.")
class WindowsPyodbcTest(unittest.TestCase):
    """
    Generic ODBC tests for Windows.
    """
    def test_local_scripts_odbc_ms_access_dsn(self):
        """
        This lists the scripts associated to ODBC dsns.
        The package pyodbc does not need to be here because it just lists Python files.
        """

        # The url is "http://rchateau-hp:8000/survol/entity.py?xid=odbc/dsn.Dsn=DSN~MS%20Access%20Database"
        instance_local_odbc = lib_client.Agent().odbc.dsn(
            Dsn="DSN=MS Access Database")

        list_scripts = instance_local_odbc.get_scripts()
        logging.debug("Scripts:")
        for one_scr in list_scripts:
            logging.debug("    %s" % one_scr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(list_scripts) > 0)

    @unittest.skipIf(is_travis_machine(), "No data sources on Travis - yet.")
    def test_all_sqldatasources(self):
        """Tests ODBC data sources"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/Databases/win32_sqldatasources_pyodbc.py")

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print("Instances")
        for one_instance in sorted(str_instances_set):
            print("    one_instance=", one_instance)


        # At least these instances must be present. Other are possible such as "DSN=dBASE Files"
        for one_str in [
            lib_uris.PathFactory().CIM_ComputerSystem(Name=CurrentMachine),
            lib_uris.PathFactory().odbc.dsn(Dsn="DSN=Excel Files"),
            lib_uris.PathFactory().odbc.dsn(Dsn="DSN=MS Access Database"),
        ]:
            print("one_str=", one_str)
            self.assertTrue(one_str in str_instances_set)


@unittest.skipIf(pyodbc is None, "pyodbc must be installed")
@unittest.skipIf(CurrentMachine != "rchateau-hp", "Local test only.")
class OraclePyodbcTest(unittest.TestCase):
    # This is the connection string of an Oracle DSN.
    # It runs on a single machine yet, specifically configured.
    oracle_dsn = "DSN=SysDataSourceSQLServer"

    def test_oracle_sqldatasources(self):
        """Tests ODBC data sources"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/Databases/win32_sqldatasources_pyodbc.py")

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        # At least these instances must be present, especially the Oracle DSN used for these tests.
        for one_str in [
            lib_uris.PathFactory().CIM_ComputerSystem(Name=CurrentMachine),
            lib_uris.PathFactory().odbc.dsn(Dsn=self.oracle_dsn),
        ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_dsn_tables(self):
        """Tests ODBC data sources"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/odbc/dsn/odbc_dsn_tables.py",
            "odbc/dsn",
            Dsn=self.oracle_dsn)

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='all_columns'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='assembly_files'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='change_tracking_tables'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='dm_broker_queue_monitors'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='dm_hadr_availability_group_states'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='dm_hadr_database_replica_cluster_states'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='dm_hadr_instance_node_map'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='server_audit_specifications'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='server_audits'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='sysusers'),
            ]:
            self.assertTrue(one_str in str_instances_set)

    def test_oracle_dsn_one_table_columns(self):
        """Tests ODBC table columns"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/odbc/table/odbc_table_columns.py",
            "odbc/table",
            Dsn=self.oracle_dsn,
            Table="dm_os_windows_info")

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        print("Instances")
        for one_instance in sorted(str_instances_set):
            print("    one_instance=", one_instance)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            lib_uris.PathFactory().odbc.column(Dsn=self.oracle_dsn, Table='dm_os_windows_info', Column='windows_service_pack_level'),
            lib_uris.PathFactory().odbc.column(Dsn=self.oracle_dsn, Table='dm_os_windows_info', Column='os_language_version'),
            lib_uris.PathFactory().odbc.column(Dsn=self.oracle_dsn, Table='dm_os_windows_info', Column='windows_release'),
            lib_uris.PathFactory().odbc.column(Dsn=self.oracle_dsn, Table='dm_os_windows_info', Column='windows_sku'),
            lib_uris.PathFactory().odbc.table(Dsn=self.oracle_dsn, Table='dm_os_windows_info'),
        ]:
            print("one_str=", one_str)
            self.assertTrue(one_str in str_instances_set)


@unittest.skipIf(pyodbc is None, "pyodbc must be installed")
@unittest.skipIf(is_platform_linux, "Windows test only.")
class SqlServerExpressPyodbcTest(unittest.TestCase):
    # This is the connection string used for all tests.
    _connection_string = r'Driver={SQL Server};Server=%s\SQLEXPRESS' % socket.gethostname()

    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_local_scripts_odbc_dsn(self):
        """
        This lists the scripts associated to ODBC dsns.
        """

        # The url is "http://rchateau-hp:8000/survol/entity.py?xid=odbc/dsn.Dsn=DSN~MS%20Access%20Database"
        instance_local_odbc = lib_client.Agent().odbc.dsn(
            Dsn=self._connection_string)

        list_scripts = instance_local_odbc.get_scripts()
        logging.debug("Scripts:")
        for one_scr in list_scripts:
            logging.debug("    %s" % one_scr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(list_scripts) > 0)

    @unittest.skip("Maybe confusion between sources and servers ? Or maybe the test does not make sense ?")
    @unittest.skipIf(is_travis_machine(), "Travis doesn't support SQL Server as a service.")
    def test_sql_server_sqldatasources(self):
        """Tests ODBC data sources"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/Databases/win32_sqldatasources_pyodbc.py")

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print("str_instances_set=", str_instances_set)

        # At least these instances must be present.
        for one_str in [
            lib_uris.PathFactory().CIM_ComputerSystem(Name=CurrentMachine),
            lib_uris.PathFactory().odbc.dsn(Dsn=self._connection_string),
        ]:
            print("one_str=", one_str)
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(is_travis_machine(), "Travis doesn't support SQL Server as a service.")
    def test_sql_server_dsn_tables(self):
        """Tests ODBC data sources"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/odbc/dsn/odbc_dsn_tables.py",
            "odbc/dsn",
            Dsn=self._connection_string)

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            lib_uris.PathFactory().odbc.table(Dsn=self._connection_string, Table='all_views'),
            ]:
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(is_travis_machine(), "Travis doesn't support SQL Server as a service.")
    def test_sql_server_dsn_one_table_columns(self):
        """Tests ODBC table columns"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/odbc/table/odbc_table_columns.py",
            "odbc/table",
            Dsn=self._connection_string,
            Table="all_views")

        # !!!
        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print("str_instances_set=", str_instances_set)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            # check a couple of columns.
            lib_uris.PathFactory().odbc.column(Dsn=self._connection_string, Table='all_views', Column='type_desc'),
            lib_uris.PathFactory().odbc.column(Dsn=self._connection_string, Table='all_views', Column='parent_object_id'),
            lib_uris.PathFactory().odbc.table(Dsn=self._connection_string, Table='all_views'),
        ]:
            self.assertTrue(one_str in str_instances_set)

# Service names:
# ... there are two standard names which are MSSQLSERVER for the default instance
# and SQLEXPRESS for the SQL Server Express edition.
# Travis starts MSSQLServer. See .travis.ymltest_sql_server_dsn_tables_pre_test

@unittest.skipIf(pyodbc is None, "pyodbc must be installed")
@unittest.skipIf(is_platform_linux, "Windows test only.")
class SqlServerNotExpressPyodbcTest(unittest.TestCase):
    # This is the connection string used for all tests.
    # This failed: node_dsn=Driver={SQL Server};Server=packer-5ef00961-da3d-8a7b-ba55-4a1e83cb951c
    # _connection_string = r'Driver={SQL Server};Server=%s' % socket.gethostname()

    # [08001] [Microsoft][ODBC SQL Server Driver][DBNETLIB]Invalid connection
    #_connection_string = r'Driver={SQL Server};Server=%s\MSSQLSERVER' % socket.gethostname()

    # Now travis.yml also installs sqlserver and starts the service.
    _connection_string = r'Driver={SQL Server};Server=%s\SQLEXPRESS' % socket.gethostname()

    @unittest.skipIf(not pyodbc, "pyodbc cannot be imported. SurvolPyODBCTest not executed.")
    def test_local_scripts_odbc_dsn(self):
        """
        This lists the scripts associated to ODBC dsns.
        """

        # The url is "http://rchateau-hp:8000/survol/entity.py?xid=odbc/dsn.Dsn=DSN~MS%20Access%20Database"
        instance_local_odbc = lib_client.Agent().odbc.dsn(
            Dsn=self._connection_string)

        list_scripts = instance_local_odbc.get_scripts()
        logging.debug("Scripts:")
        for one_scr in list_scripts:
            logging.debug("    %s" % one_scr)
        # There should be at least a couple of scripts.
        self.assertTrue(len(list_scripts) > 0)

    @unittest.skip("Maybe confusion between sources and servers ? Or maybe the test does not make sense ?")
    @unittest.skipIf(is_travis_machine(), "Travis doesn't support SQL Server as a service.")
    def test_sql_server_sqldatasources(self):
        """Tests ODBC data sources"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/Databases/win32_sqldatasources_pyodbc.py")

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print("str_instances_set=", str_instances_set)

        # At least these instances must be present.
        for one_str in [
            lib_uris.PathFactory().CIM_ComputerSystem(Name=CurrentMachine),
            lib_uris.PathFactory().odbc.dsn(Dsn=self._connection_string),
        ]:
            print("one_str=", one_str)
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(is_travis_machine(), "Travis doesn't support SQL Server as a service.")
    def test_sql_server_dsn_tables_pre_test(self):
        # If this does not work, no point going further
        # This failed: node_dsn=Driver={SQL Server};Server=packer-5ef00961-da3d-8a7b-ba55-4a1e83cb951c
        cnxn = pyodbc.connect(self._connection_string)
        self.assertTrue(cnxn is not None)
        cursor = cnxn.cursor()
        for row in cursor.tables():
            print("row.table_name=", row.table_name)
            self.assertTrue(row.table_name is not None)

    @unittest.skipIf(is_travis_machine(), "Travis doesn't support SQL Server as a service.")
    def test_sql_server_dsn_tables(self):
        """Tests ODBC data sources"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/odbc/dsn/odbc_dsn_tables.py",
            "odbc/dsn",
            Dsn=self._connection_string)

        str_instances_set = set([str(one_inst) for one_inst in lst_instances])

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            lib_uris.PathFactory().odbc.table(Dsn=self._connection_string, Table='all_views'),
            ]:
            self.assertTrue(one_str in str_instances_set)

    @unittest.skipIf(is_travis_machine(), "Travis doesn't support SQL Server as a service.")
    @unittest.skip("NOT YET")
    def test_sql_server_dsn_one_table_columns(self):
        """Tests ODBC table columns"""

        lst_instances = _client_object_instances_from_script(
            "sources_types/odbc/table/odbc_table_columns.py",
            "odbc/table",
            Dsn=self._connection_string,
            Table="all_views")

        # !!!
        str_instances_set = set([str(one_inst) for one_inst in lst_instances])
        print("str_instances_set=", str_instances_set)

        # Checks the presence of some Python dependencies, true for all Python versions and OS platforms.
        for one_str in [
            # check a couple of columns.
            lib_uris.PathFactory().odbc.column(Dsn=self._connection_string, Table='all_views', Column='type_desc'),
            lib_uris.PathFactory().odbc.column(Dsn=self._connection_string, Table='all_views', Column='parent_object_id'),
            lib_uris.PathFactory().odbc.table(Dsn=self._connection_string, Table='all_views'),
        ]:
            self.assertTrue(one_str in str_instances_set)


@unittest.skipIf(pyodbc is None, "pyodbc must be installed")
@unittest.skip("This is only for debugging purpose")
class PyOdbcBasicsTest(unittest.TestCase):

    # Local test machine, Windows 7.
    # one_driver= SQL Server
    # one_driver= SQL Server Native Client 11.0
    # one_driver= Oracle in XE
    # one_driver= MySQL ODBC 5.3 ANSI Driver
    # one_driver= MySQL ODBC 5.3 Unicode Driver

    # Travis Win10:
    # one_driver= SQL Server
    # and with: choco install sqlserver-odbcdriver :
    # one_driver= ODBC Driver 17 for SQL Server
    def test_drivers_list(self):
        for one_driver in pyodbc.drivers():
            print("one_driver=", one_driver)
        self.assertTrue(False)

    # Local test machine, Windows 7.
    # one_data_source= MyNativeSqlServerDataSrc
    # one_data_source= Excel Files
    # one_data_source= SqlSrvNativeDataSource
    # one_data_source= mySqlServerDataSource
    # one_data_source= MyOracleDataSource
    # one_data_source= SysDataSourceSQLServer
    # one_data_source= dBASE Files
    # one_data_source= OraSysDataSrc
    # one_data_source= MS Access Database

    # Travis Win10:
    # (nothing)
    def test_data_sources_list(self):
        for one_data_source in pyodbc.dataSources():
            print("one_data_source=", one_data_source)
        self.assertTrue(False)


