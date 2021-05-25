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

from sources_types import odbc as survol_odbc


class MatchesAggregationTest(unittest.TestCase):
    # Things to test:
    # - From bytes.
    # - From UTF8, on one, two or four bytes.

    def test_aggregate_dsn_pieces(self):
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
connection_strings_light = [
    r'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=C:\AnyDir\AnyFile.tmp;',
    r'Provider=Microsoft.Jet.OLEDB.4.0;Data Source=c:\txtFilesFolder\;',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=C:\Documents;',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=c:\myFolder\myExcel2007file.xlsx;',
    r'Provider=Microsoft.ACE.OLEDB.12.0;Data Source=c:\myFolder\myBinaryExcel2007file.xlsb;',
]

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

# Various text strings to be added before and after.
noise_text = [
    " lksdj;laksjdf;lkajsdf",
    " 9087sdva98uvohj.134mn5.23m4 ",
    " -098_)( *76586 ",
    " nothing=something ",
    " ;==; ",
]


class DetectConnectionStringTest(unittest.TestCase):

    # Things to test:
    # - From bytes.
    # - From UTF8, on one, two or four bytes.

    def _aux_test_from_python_bytes(self, text_display, the_odbc_regex, various_connections):
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
                    #matched_connect = compiled_regex.findall(bytes_array)

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
