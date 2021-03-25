"""
ODBC Data Source Name
"""

import sys
import logging

import pyodbc

import lib_uris
import lib_util
import lib_credentials
from lib_properties import pc
from sources_types import odbc as survol_odbc
from sources_types.sqlserver import dsn as survol_sqlserver_dsn
from sources_types.oracle import db as oracle_db

# On Linux pyodbc is installed with, for example:
# yum install unixODBC-devel
# https://stackoverflow.com/questions/31353137/sql-h-not-found-when-installing-pyodbc-on-heroku


def Graphic_colorfill():
    return "#CCFF11"


def Graphic_colorbg():
    return "#CCFF11"


def EntityOntology():
    return ([survol_odbc.CgiPropertyDsn()],)


def MakeUri(dsn_name):
    return lib_uris.gUriGen.UriMakeFromDict("odbc/dsn", {survol_odbc.CgiPropertyDsn(): dsn_name})


def EntityName(entity_ids_arr):
    return survol_odbc.CgiPropertyDsn().ValueDisplay(entity_ids_arr[0])


# This expects a DSN as a simple string.
def MakeOdbcConnectionStringFromDsn(dsn_nam):
    pair_usrnam_pass = lib_credentials.GetCredentials("ODBC", dsn_nam)
    # With SqlServer, there is some implicit connection if this is the local machine.
    if pair_usrnam_pass[0] == "":
        # Maybe we could add ";Trusted_Connection=yes"
        connect_str = "DSN=%s" % dsn_nam
    else:
        connect_str = "DSN=%s;UID=%s;PWD=%s" % (dsn_nam, pair_usrnam_pass[0], pair_usrnam_pass[1])

    return connect_str


# This can be just a string, a DSN. Or a connection string.
# This function is very tolerant.
def MakeOdbcConnectionString(dsn_nam):
    split_tokens = [strpTok.strip().split("=") for strpTok in dsn_nam.split(";")]

    # Maybe this is a single string, so we add "DSN" and look for username/password.
    if len(split_tokens) == 1:
        if len(split_tokens[0]) == 1:
            return MakeOdbcConnectionStringFromDsn(split_tokens[0][0])

    # Otherwise it assumes that it contains all needed connection parameters: User, password.
    # This might be checked, or if it contains FileDsn=... etc.

    # Otherwise it assumes a connection string, returned "as is".
    return dsn_nam


def GetDatabaseEntityTypeFromConnection(cnxn):
    # "Oracle", "Microsoft SQL Server"
    prm_value = cnxn.getinfo(pyodbc.SQL_DBMS_NAME)

    dict_db_to_entity = {
        "Oracle": "oracle",
        "Microsoft SQL Server": "sqlserver"
    }

    try:
        return dict_db_to_entity[prm_value]
    except KeyError:
        # TODO: Or maybe return "sql" to be consistent with the concept of vendor-neutral database.
        return ""


def GetDatabaseEntityType(dsn_nam):
    odbc_connect_string = MakeOdbcConnectionString(dsn_nam)

    cnxn = pyodbc.connect(odbc_connect_string)

    return GetDatabaseEntityTypeFromConnection(cnxn)


def AddInfo(grph, node, entity_ids_arr):
    """"
    This displays links to the Oracle database, not seen from ODBC,
    so we can have more specific queries.
    """""
    dsn_nam = entity_ids_arr[0]

    odbc_connect_string = MakeOdbcConnectionString(dsn_nam)

    try:
        cnxn = pyodbc.connect(odbc_connect_string)
    except Exception as exc:
        grph.add((node, pc.property_information, lib_util.NodeLiteral(str(exc))))
        return

    db_entity_type = GetDatabaseEntityTypeFromConnection(cnxn)

    logging.debug("AddInfo db_entity_type=%s", db_entity_type)
    if db_entity_type == "oracle":
        # For example "XE".
        server_name = cnxn.getinfo(pyodbc.SQL_SERVER_NAME)
        node_oradb = oracle_db.MakeUri(server_name)

        grph.add((node, pc.property_oracle_db, node_oradb))

    elif db_entity_type == "sqlserver":
        # We stick to the DSN because it encloses all the needed information.
        node_sqlserverdb = survol_sqlserver_dsn.MakeUri(dsn_nam)

        grph.add((node, pc.property_sqlserver_db, node_sqlserverdb))
        logging.debug("AddInfo db_entity_type=%s ADDING NODE", db_entity_type)


# TODO: Maybe should decode ????
def GetDsnNameFromCgi(cgiEnv):
    key_word_dsn = survol_odbc.CgiPropertyDsn()
    dsn_coded = cgiEnv.m_entity_id_dict[key_word_dsn]
    dsn_decoded = key_word_dsn.ValueDecode(dsn_coded)

    return dsn_decoded


def DatabaseEnvParams(processId):
    # TODO: We could use the process id to check if the process executable is linked
    # with the SQLServer shareable library.

    # We do not list sources in lib_credentials because some ODBC sources
    # can be accessed without pass word (With Windows validation).
    sources_data = pyodbc.dataSources()

    # {
    #     'MyNativeSqlServerDataSrc': 'SQL Server Native Client 11.0',
    #     'Excel Files': 'Microsoft Excel Driver (*.xls, *.xlsx, *.xlsm, *.xlsb)',
    #     'SqlSrvNativeDataSource': 'SQL Server Native Client 11.0',
    #     'mySqlServerDataSource': 'SQL Server',
    #     'MyOracleDataSource': 'Oracle in XE',
    #     'SysDataSourceSQLServer': 'SQL Server',
    #     'dBASE Files': 'Microsoft Access dBASE Driver (*.dbf, *.ndx, *.mdx)',
    #     'OraSysDataSrc' : 'Oracle in XE',
    #     'MS Access Database': 'Microsoft Access Driver (*.mdb, *.accdb)'
    # }

    dsn_list = ({survol_odbc.CgiPropertyDsn(): "DSN=" + dsn } for dsn in sources_data)

    return "sqlserver/query", dsn_list
