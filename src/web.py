# TODO
# - add generic web query function

from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import result
from urllib.parse import urlparse
import urllib.parse
import time
import json
import argparse
# import sys
import logging
import ipaddress
import sqlite3
from os.path import exists
import requests
import mariadb
# import mysql.connector
import socketserver
import http.server
import colorlog
from colorlog import ColoredFormatter
from threading import Thread

# ----
# mac notes - fix urllib warnings
# pip uninstall urllib3
# pip install 'urllib3<2.0'
# ----

# defaults
parser = argparse.ArgumentParser(description="Just an example",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--hostname", help="Host or IP to bind to", default="localhost")
parser.add_argument("--port", help="Port to bind to (TCP)", default="8080")
parser.add_argument("--log", help="Output Log File", default="web.log")
parser.add_argument('--exit', action=argparse.BooleanOptionalAction)
parser.add_argument("--lookup")
parser.add_argument("--key")
parser.add_argument('--verbose', action=argparse.BooleanOptionalAction)
parser.add_argument('--debug', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--ignore_sqlite', action=argparse.BooleanOptionalAction)
parser.add_argument("--db", help="Sqlite DB File", default="searches.db")
parser.add_argument('--log_response', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--cache-mariadb', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument('--debug-save-in-mariadb-cache', action=argparse.BooleanOptionalAction, default=True)
parser.add_argument("--console-level", default="INFO")
parser.add_argument("--log-level", default="INFO")
parser.add_argument("--vt-api-key", default="")

args = parser.parse_args()
configFromArg = vars(args)

logger = logging.getLogger('PythonGraylogLookupsWeb')
logger.setLevel(logging.DEBUG)

hostName = str(configFromArg['hostname'])
serverPort = int(configFromArg['port'])
logFile = str(configFromArg['log'])
sDbFileName = args.db

mariadb_host = "127.0.0.1"
mariadb_port = 3306
mariadb_user = "root"
mariadb_pass = ""
MARIADB_FAIL_FATAL = True
MARIADB_FAIL_NOTFATAL = False

def getUnixTimeUtc():
    from datetime import datetime
    utime = datetime.utcnow().timestamp()
    return int(round(utime, 0))

def getDbCur(sArgDbFile):
    con = sqlite3.connect(sArgDbFile)
    cur = con.cursor()
    return {"con": con, "cur": cur}

def dbExecute(sArgDbFile, stmnt):
    if args.debug == False:
        cur = getDbCur(sArgDbFile)['cur']

        try:
            # cur.execute('CREATE TABLE "rdns" ("ip" TEXT,"name" TEXT,"has_lookup" INTEGER DEFAULT 0);')
            cur.execute(stmnt)

        except Exception as e:
            # print(e)
            # print(errorText + "ERROR, failed to create table `rdns`" + defText)
            a = 1
    else:
        print("DEBUG: Skipping dbCreateTable()")

def initDb(sArgDbFile):
    create_table_statement = 'CREATE TABLE "rdns" ("ip" TEXT, "name" TEXT, "has_lookup" INTEGER DEFAULT 0, "ttl" INTEGER DEFAULT 86400, "date_created" INTEGER DEFAULT 0);'

    if exists(sArgDbFile):
        cur = getDbCur(sArgDbFile)['cur']
        # cur.execute("CREATE TABLE rdns(ip, name)")
        try:
            res = cur.execute("SELECT ip, name, has_lookup FROM rdns")
        except:
            print("Creating database using " + str(sArgDbFile))
            dbExecute(sArgDbFile, create_table_statement)
        
        try:
            res = cur.execute("SELECT ttl FROM rdns")
        except:
            print("Adding 'ttl' column using " + str(sArgDbFile))
            dbExecute(sArgDbFile, 'ALTER TABLE rdns ADD "ttl" INTEGER DEFAULT 86400')
        
        try:
            res = cur.execute("SELECT date_created FROM rdns")
        except:
            print("Adding 'date_created', 'date_created' column using " + str(sArgDbFile))
            dbExecute(sArgDbFile, 'ALTER TABLE rdns ADD "date_created" INTEGER DEFAULT 0')
        
    else:
        print("Creating database using " + str(sArgDbFile))
        dbExecute(sArgDbFile, create_table_statement)

def mariadb_get_cur(mdb_hostname: str, mdb_port: int, mdb_username: str, mdb_password: str, b_fail_fatal: bool):
    # Connect to MariaDB Platform
    try:
        conn = mariadb.connect(
            user=mdb_username,
            password=mdb_password,
            host=mdb_hostname,
            port=mdb_port,
            database="graylog_lookups"
        )
        # Get Cursor
        cur = conn.cursor()
        return {
            "cursor": cur,
            "conn": conn
        }
    except mariadb.Error as e:
        logging.error(f"[[mariadb_get_cur]] Error connecting to MariaDB Platform: {e}")
        if "Unknown database" in str(e):
            return {
                "error": "unknown database"
            }
        elif "(36)" in str(e):
            if b_fail_fatal == True:
                logging.critical("[[mariadb_get_cur]] cannot connect - exit(1)")
                exit(1)
            return {
                "error": "cannot connect"
            }
        else:
            if b_fail_fatal == True:
                logging.critical("[[mariadb_get_cur]] error - exit(1)")
                exit(1)
            else:
                logging.error("[[mariadb_get_cur]] ERROR! Fatal MariaDB error but continuing.")
                return {
                    "error": str(e)
                }


def create_cache_db(mdb_hostname: str, mdb_port: int, mdb_username: str, mdb_password: str):
    # mydb = mysql.connector.connect(
    #     host=mdb_hostname,
    #     port=mdb_port,
    #     user=mdb_username,
    #     password=mdb_password
    # )
    # mycursor = mydb.cursor()
    # mycursor.execute("CREATE DATABASE graylog_lookups")

    try:
        conn = mariadb.connect(
            user=mdb_username,
            password=mdb_password,
            host=mdb_hostname,
            port=mdb_port
        )
    except mariadb.Error as e:
        logging.error(f"[[create_cache_db]] Error connecting to MariaDB Platform: {e}")
    
    try:
        cur = conn.cursor()
        cur.execute("CREATE DATABASE graylog_lookups")
    except mariadb.Error as e:
        logging.error(f"[[create_cache_db]] Error connecting to MariaDB Platform: {e}")

def get_table_create_sql(tablename: str):
    sql = ""

    if tablename == "rdns":

        # ip            TEXT
        # name          TEXT
        # has_lookup    INT (0/1)
        # ttl           INT
        # date_created  INT

        sql = ('CREATE TABLE rdns (' + '\n' +
                    'uid MEDIUMINT NOT NULL AUTO_INCREMENT,' + '\n' +
                    'ip VARCHAR(15) NOT NULL,' + '\n' +
                    'name TEXT,' + '\n' +
                    'has_lookup TINYINT(1) DEFAULT 0 NOT NULL,' + '\n' +
                    # 'lookup_source VARCHAR(255) DEFAULT \'\' NOT NULL,' + '\n' +
                    'ttl VARCHAR(15) NULL,' + '\n' +
                    'date_created VARCHAR(15) NOT NULL,' + '\n' +
                    'PRIMARY KEY (uid)' + '\n' +
                ');')
    elif tablename == "migrations":

        # ip            TEXT
        # name          TEXT
        # has_lookup    INT (0/1)
        # ttl           INT
        # date_created  INT

        sql = ('CREATE TABLE migrations (' + '\n' +
                    'uid MEDIUMINT NOT NULL AUTO_INCREMENT,' + '\n' +
                    'mig_name VARCHAR(255) NULL,' + '\n' +
                    'data TEXT,' + '\n' +
                    'PRIMARY KEY (uid)' + '\n' +
                ');')
    
    return sql

def does_table_exist(cur, tablename: str):
    str_sql = "SELECT * FROM " + str(tablename)

    try:
        cur.execute(str_sql)
    except mariadb.Error as e:
        return False
    
    return True

def create_cache_table(cur, tablename: str):
    # Obtain SQL
    table_create_sql = get_table_create_sql(tablename)
    
    # Execute SQL
    cur.execute(table_create_sql)
    
    # Verify Table was successfully created
    b_table_exists = does_table_exist(cur, tablename)
    if b_table_exists == False:
        logging.critical(f"[[create_cache_table]] ERROR: Failed to create cache table: " + str(tablename))
        exit(1)

def run_init_db_mig(conn, cur, migration_name: str):
    logging.debug("[[run_init_db_mig]] running migration: " + str(migration_name))

    if migration_name == "rdns_column_add_lookup_source":
        sql = ('ALTER TABLE rdns' + '\n' +
                    'ADD COLUMN lookup_source VARCHAR(255) DEFAULT \'\' NOT NULL AFTER has_lookup' + '\n' +
                ';')
    elif migration_name == "rdns_column_alter_uid_int":
        sql = ('ALTER TABLE rdns' + '\n' +
                    'MODIFY COLUMN uid INT auto_increment NOT NULL' + '\n' +
                ';')
    else:
        return False
    
    try:
        cur.execute(sql)
        conn.commit()
    except mariadb.Error as e:
        logging.error(f"[[run_init_db_mig]] Error: {e}")
        return False
    
    save_mig_state = "INSERT INTO migrations (mig_name) VALUES ('" + str(migration_name) + "')"
    try:
        cur.execute(save_mig_state)
        conn.commit()
    except mariadb.Error as e:
        logging.error(f"[[run_init_db_mig]] Error: {e}")
        return False
    
    return True

def init_cache_db(hostname: str, port: int, username: str, password: str):
    # test if DB exists
    rs_cur = mariadb_get_cur(hostname, port, username, password, MARIADB_FAIL_NOTFATAL)
    if not rs_cur:
        return False

    if "error" in rs_cur:
        if rs_cur['error'] == "unknown database":
            logging.info("[[init_cache_db]] database missing let us create it!")

            # create missing database
            create_cache_db(hostname, port, username, password)
            # retest
            rs_cur = mariadb_get_cur(hostname, port, username, password, MARIADB_FAIL_NOTFATAL)
            if "error" in rs_cur:
                return False
        elif rs_cur['error'] == "cannot connect":
            return False
        
    # init tables?
    l_cache_tables = []
    l_cache_tables.append("rdns")
    l_cache_tables.append("migrations")

    l_existing_tables = []

    # get list of tables
    # l_tables = exec_query_db(rs_cur, "show tables")
    rs_cur["cursor"].execute("show tables")
    if rs_cur["cursor"]:
        for table_name in rs_cur["cursor"]:
            if len(table_name):
                # print(table_name[0])
                l_existing_tables.append(str(table_name[0]))
    conn = rs_cur["conn"]

    for table_name in l_cache_tables:
        if not table_name in l_existing_tables:
            logging.info("[[init_cache_db]] Table does not exist, we need to create it: " + str(table_name))
            create_cache_table(rs_cur["cursor"], str(table_name))

    # migrations
    l_migrations = []
    l_migrations.append("rdns_column_add_lookup_source")
    l_migrations.append("rdns_column_alter_uid_int")

    l_existing_mig = []
    
    rs_cur["cursor"].execute("SELECT mig_name FROM migrations")
    if rs_cur["cursor"]:
        for existing_mig in rs_cur["cursor"]:
            l_existing_mig.append(str(existing_mig[0]))
    
    for mig_to_verify in l_migrations:
        if not mig_to_verify in l_existing_mig:
            logging.warning("[[init_cache_db]] migration '" + str(mig_to_verify) + " has not run.")
            run_init_db_mig(conn, rs_cur["cursor"], mig_to_verify)

    conn.close()

    return True

def mariadb_type_helper(input):
    # return "'" + str(input) + "'"

    if type(input) == int:
        return str(input)
    else:
        return "'" + str(input) + "'"

def convert_dict_to_sql_insert(table_name: str, dict_to_use_to_build: dict):
    str_sql = "INSERT INTO " + str(table_name) + " ("
    
    i_fields = 0
    for item in dict_to_use_to_build:
        # print(item + ": " + str(dict_to_use_to_build[item]))
        if i_fields > 0:
            str_sql = str_sql + ", "
        str_sql = str_sql + item
        i_fields = i_fields +1
    
    str_sql = str_sql + ") "
    str_sql = str_sql + " VALUES ("

    i_fields = 0
    for item in dict_to_use_to_build:
        # print(item + ": " + str(dict_to_use_to_build[item]))
        if i_fields > 0:
            str_sql = str_sql + ", "
        
        str_sql = str_sql + str(mariadb_type_helper(dict_to_use_to_build[item]))
        i_fields = i_fields +1

    str_sql = str_sql + ")"
    
    return str_sql

def save_lookup_in_cache(lookup_table: str, dict_to_cache: dict):
    b_error = True
    str_sql = convert_dict_to_sql_insert(lookup_table, dict_to_cache)
    rs_cur = mariadb_get_cur(mariadb_host, mariadb_port, mariadb_user, mariadb_pass, MARIADB_FAIL_NOTFATAL)
    if rs_cur:
        if "cursor" in rs_cur and "conn" in rs_cur:
            cur = rs_cur["cursor"]
            conn = rs_cur["conn"]
            b_error = False

    if b_error == True:
        return False

    try:
        # print(str_sql)
        cur.execute(str_sql)
        # print(f"{cur.rowcount} details inserted")
        conn.commit()
        conn.close()
        logging.debug("[[save_lookup_in_cache]] cached: [" + str(lookup_table) + "] " + str(json.dumps(dict_to_cache)))
    except mariadb.Error as e:
        conn.close()
        logging.error(f"[[save_lookup_in_cache]] Error: {e} ::: [" + str(lookup_table) + "] " + str(json.dumps(dict_to_cache)))

def delete_lookup_in_cache(lookup_table: str, lookup_key: str):
    b_error = True
    str_sql = "DELETE FROM " + str(lookup_table) + " WHERE ip = '" + str(lookup_key) + "'"
    rs_cur = mariadb_get_cur(mariadb_host, mariadb_port, mariadb_user, mariadb_pass, MARIADB_FAIL_NOTFATAL)

    if rs_cur:
        if "cursor" in rs_cur and "conn" in rs_cur:
            cur = rs_cur["cursor"]
            conn = rs_cur["conn"]
            b_error = False

    if b_error == True:
        return False

    try:
        # print(str_sql)
        cur.execute(str_sql)
        # print(f"{cur.rowcount} details inserted")
        conn.commit()
        conn.close()
        logging.debug("[[delete_lookup_in_cache]] deleted: [" + str(lookup_table) + "] " + str(lookup_key))
    except mariadb.Error as e:
        conn.close()
        logging.error(f"[[delete_lookup_in_cache]] Error: {e}")

def list_to_numbers(input_list: list):
    d = {}
    i = 0
    for item in input_list:
        d[item] = i
        i = i + 1
    return d

def cache_result_format(lookup_table: str, row):
    dict_field_pos = {}
    dict_field_pos["rdns"] = ["uid", "ip", "name", "has_lookup", "lookup_source", "ttl", "date_created"]
    
    lookup_list_field_pos = list_to_numbers(dict_field_pos[lookup_table])

    if lookup_table == "rdns":
        if row:
            return {
                "ip": row[lookup_list_field_pos["ip"]],
                "name": row[lookup_list_field_pos["name"]],
                "has_lookup": row[lookup_list_field_pos["has_lookup"]],
                "ttl": row[lookup_list_field_pos["ttl"]],
                "date_created": row[lookup_list_field_pos["date_created"]]
            }
    
    return {}

def get_lookup_from_cache(lookup_table: str, lookup_key: str):
    b_error = True
    str_sql = "SELECT * FROM " + str(lookup_table) + " WHERE ip = '" + str(lookup_key) + "' ORDER BY date_created DESC LIMIT 1"
    rs_cur = mariadb_get_cur(mariadb_host, mariadb_port, mariadb_user, mariadb_pass, MARIADB_FAIL_NOTFATAL)

    if rs_cur:
        if "cursor" in rs_cur and "conn" in rs_cur:
            cur = rs_cur["cursor"]
            conn = rs_cur["conn"]
            b_error = False

    if b_error == True:
        return {}

    try:
        cur.execute(str_sql)
        row = cur.fetchone()
        final_return = cache_result_format(lookup_table, row)
        conn.close()
        return final_return

    except mariadb.Error as e:
        conn.close()
        logging.error(f"[[get_lookup_from_cache]] Error: {e}")

def getDbRow(sArgDbFile, strSql):
    if exists(sArgDbFile):
        cur = getDbCur(sArgDbFile)['cur']
        try:
            res = cur.execute(strSql)
            ip, name, has_lookup, ttl, date_created = res.fetchone()

            if has_lookup == int(1):
                bHasLookup = True
            else:
                bHasLookup = False

            dRs = {
                "ip": ip,
                "name": name,
                "has_lookup": bHasLookup,
                "ttl": ttl,
                "date_created": date_created
            }
            return dRs
        
        except Exception as e:
            # print(e)
            # dbCreateTable(sArgDbFile)
            a = 1
            return {}

def deleteIp(sArgDbFile, sArgIp):
    print("Deleting IP: " + str(sArgIp))

    oDb = getDbCur(sArgDbFile)
    cur = oDb['cur']
    con = oDb['con']
    try:
        sSqlExec = "DELETE FROM rdns WHERE ip = '" + str(sArgIp) + "'"
        cur.execute(sSqlExec)
        con.commit()
    except Exception as e:
        a = 1

def addTimeoutIp(sArgDbFile, sArgIp, sArgHostname):
    print("Adding IP to cache: " + str(sArgIp))
    # add IP address to sqllite db, will only add if does not already exist
    oDb = getDbCur(sArgDbFile)
    cur = oDb['cur']
    con = oDb['con']

    # does exist?
    res = cur.execute("SELECT * FROM rdns WHERE ip = '" + str(sArgIp) + "'")
    bExists = False
    for row in res:
        bExists = True
        break

    if len(sArgHostname) > 0:
        has_lookup = 1
    else:
        has_lookup = 0

    if bExists == False:
        # Insert, does not already exist
        try:
            unix_time = str(getUnixTimeUtc())
            sSqlExec = "INSERT INTO rdns VALUES ('" + str(sArgIp) + "', '" + str(sArgHostname) + "', '" + str(has_lookup) + "', 604800, " + unix_time + ")"
            print(sSqlExec)
            cur.execute(sSqlExec)
            con.commit()
            
        except Exception as e:
            # print(e)
            # print("ERROR, failed insert for ip '" + str(sArgIp) + "'")
            a = 1

def get_ipv4_by_hostname(hostname):
    import socket
    rs = socket.gethostbyname(hostname)
    return rs

def get_domain_name(ip_address):
    import socket
    socket.setdefaulttimeout(5)

    try:
        result=socket.gethostbyaddr(ip_address)
        result = list(result)[0]
    except Exception as e:
        result = {"exception": e}

    return result

def validate_ip_address(ip_string):
    try:
        ip_object = ipaddress.ip_address(ip_string)
        # logging.debug("[[validate_ip_address]] The IP address '{ip_object}' is valid.")
        return True
    except ValueError:
        return False
        # logging.debug("[[validate_ip_address]] The IP address '{ip_string}' is not valid")
    
    return False

def validate_ip_addr_ver(ip_string: str, ip_ver: int):
    if not validate_ip_address(ip_string):
        return False

    if ip_ver == 4:
        if ":" in ip_string:
            return False
        else:
            return True
    elif ip_ver == 6:
        if ":" in ip_string:
            return True
        else:
            return False
    
    return False

def lookupRDns(argQuery):
    # log to filter out/ignore
    #   255.255.255.255
    #   private IP
    #       127.0.0.0/8 (127.0.0.0 - 127.255.255.255)
    #       10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    #       127.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    #       192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
    #   multicast/broadcast

    cache_record = {}
    if args.cache_mariadb == True:
        cache_record = get_lookup_from_cache("rdns", str(argQuery))

    # logging.debug("cache_record: " + str(cache_record))

    if cache_record and 'has_lookup' in cache_record:
        str_cached_result_returned = {
            "value": cache_record['name'],
            "lookup": argQuery,
            "meta": "Returned via mariadb cache",
            "cached": 1
        }

        # logging.debug("Cache record returned: " + str(cache_record))
        # check for TTL expiration
        unix_time_now_utc = getUnixTimeUtc()
        if 'ttl' in cache_record and 'date_created' in cache_record:
            ttl = cache_record['ttl']
            date_created = cache_record['date_created']
            int_ttl_compare = int(ttl) + int(date_created)
            # logging.debug("ttl: " + str(ttl) + ", date_created: " + str(date_created) + "\n" + "Is " + str(int_ttl_compare) + " < " + str(unix_time_now_utc))
            if int(int_ttl_compare) < int(unix_time_now_utc):
                logging.debug("Cache TTL Expired, deleting cached record: rdns," + str(argQuery))
                delete_lookup_in_cache("rdns", str(argQuery))
            else:
                return str_cached_result_returned
        else:
            if 'has_lookup' in cache_record and int(cache_record['has_lookup']) == 0:
                logging.info("Cache record has no hostname saved: " + str(argQuery))
                return {"value": ""}
            else:
                return str_cached_result_returned
    else:
        logging.debug("NO Cache record found for: " + str(argQuery))

    lIgnoreThese = ["239.255.255.250", "255.255.255.255"]

    bGiveResult = True

    if str(argQuery) in lIgnoreThese:
        bGiveResult = False
    
    # ignore lookups for local networks 192.168.0.0 - 192.168.255.255
    elif ipaddress.ip_address(str(argQuery)) in ipaddress.ip_network('192.168.0.0/16'):
        # allow lookups for 192.168.100.1
        if not str(argQuery) =="192.168.100.1":
            # allow lookups for 192.168.0.0 - 192.168.0.255
            if not ipaddress.ip_address(str(argQuery)) in ipaddress.ip_network('192.168.0.0/24'):
                bGiveResult = False
    elif ipaddress.ip_address(str(argQuery)) in ipaddress.ip_network('10.0.0.0/8'):
        bGiveResult = False
    elif ipaddress.ip_address(str(argQuery)) in ipaddress.ip_network('127.16.0.0/12'):
        bGiveResult = False
    elif ipaddress.ip_address(str(argQuery)) in ipaddress.ip_network('127.0.0.0/8'):
        bGiveResult = True
        result = "localhost"

    if bGiveResult == False:
        return {
            "value": "",
            "meta": "query ignored, no result returned."
        }
    else:
        result = get_domain_name(argQuery)

        dict_to_cache = {
            "ip": str(argQuery),
            "name": str(result),
            "ttl": 604800,
            "lookup_source": "dns",
            "date_created": getUnixTimeUtc()
        }
        if len(result) > 0:
            has_lookup = 1
        else:
            has_lookup = 0
        dict_to_cache["has_lookup"] = has_lookup

        if "exception" in result:
            # if configFromArg['verbose'] == True:
            #     print("exeption is in result")
            # add to db for future exclusion
            addTimeoutIp(sDbFileName, argQuery, '')
            return result
        else:
            addTimeoutIp(sDbFileName, argQuery, result)
            if args.debug_save_in_mariadb_cache == True:
                b_is_ip = validate_ip_addr_ver(str(argQuery), 4)
                if b_is_ip == True:
                    save_lookup_in_cache("rdns", dict_to_cache)

        return {
            "value": result,
            "meta": "returned from rDNS query",
            "cached": 0
        }

def lookupDns(argQuery):
    result = get_ipv4_by_hostname(argQuery)
    return {
        "value": result,
        "meta": "returned from DNS query",
        "cached": 0
    }

def anomUrl(argQuery):
    oArgs = parseArgs(argQuery)
    # build URL
    # http://graylog.drew.local:9000/search?q=source%3Apfsense+AND+_exists_%3Aquery_request_length&rangetype=absolute&from=2022-12-12T11%3A41%3A51.366Z&to=2022-12-12T11%3A56%3A51.366Z
    # http://graylog.drew.local:9000/search?q=source:pfsense AND _exists_:query_request_length&rangetype=absolute&from=2022-12-12%2005:41:51.366Z&to=2022-12-12%2005:56:51.366Z
    # search?q=source:pfsense+AND+_exists_:query_request_length&rangetype=absolute&from=2022-12-12T11:41:51.366Z&to=2022-12-12T11:56:51.366Z
    strConcat = ""
    strConcat = strConcat + "http://graylog.drew.local:9000/"
    strConcat = strConcat + "search?q=" + "source:pfsense AND _exists_:query_request_length"
    strConcat = strConcat + "&rangetype=absolute"

    startTime = urllib.parse.unquote(oArgs['anomaly_data_start_time'])
    startTime = startTime.replace(" ", "T")
    strConcat = strConcat + "&from=" + startTime + "Z"
    
    endTime = urllib.parse.unquote(oArgs['anomaly_data_end_time'])
    endTime = endTime.replace(" ", "T")
    strConcat = strConcat + "&to=" + endTime + "Z"
    return strConcat

def mergeDict(dictOrig: dict, dictToAdd: dict, allowReplacements: bool):
    for item in dictToAdd:
        
        bSet = True
        if item in dictOrig:
            if allowReplacements == False:
                bSet = False
        
        if bSet == True:
            dictOrig[item] = dictToAdd[item]
    
    return dictOrig

def query_virus_total(query_arg_key: str, query_type: str):

    if len(args.vt_api_key) == 0:
        logging.error("no virus total api key specified. Use --vt-api-key")
        return {
            "success": False,
            "exception": "ERROR! no virus total api key specified. Use --vt-api-key"
        }

    sUrl = "https://www.virustotal.com/api/v3/" + str(query_type) + "/" + str(query_arg_key)

    sHeaders = {
            "Accept":"application/json",
            "X-Requested-By":"python-requests",
            "x-apikey": args.vt_api_key
        }
    # sHeaders = mergeDict(sHeaders, {}, True)

    args_for_req = {}
    args_for_req["url"] = sUrl
    # args_for_req["json"] = argJson
    args_for_req["headers"] = sHeaders
    # args_for_req["verify"] = False
    # args_for_req["auth"] = HTTPBasicAuth(sArgUser, sArgPw)

    try:
        # r = requests.delete(sUrl, json = argJson, headers=sHeaders, verify=False, auth=HTTPBasicAuth(sArgUser, sArgPw))
        r = requests.get(**args_for_req)

        # print(r.status_code)
        # print(r.headers)
        # print(r.text)
        # exit()
        return json.loads(r.text)
    except Exception as e:
        return {
            "success": False,
            "exception": e
        }

def translateMask(argHexMask):
    # return argHexMask
    iDec = int(argHexMask, 16)

    sOutputMask = []

    dMaskSchema = {}
    
    dMaskSchema["16777216"] = "ACCESS_SYS_SEC"
    dMaskSchema["1048576"] = "SYNCHRONIZE"
    dMaskSchema["524288"] = "WRITE_OWNER"
    dMaskSchema["262144"] = "WRITE_DAC"
    dMaskSchema["131072"] = "READ_CONTROL"
    dMaskSchema["65536"] = "DeleteChild"
    dMaskSchema["256"] = "WriteAttributes"
    dMaskSchema["128"] = "ReadAttributes"
    dMaskSchema["64"] = "DeleteChild"
    dMaskSchema["32"] = "Execute/Traverse"
    dMaskSchema["16"] = "WriteExtendedAttr"
    dMaskSchema["8"] = "ReadExtendedAttr"
    dMaskSchema["4"] = "AppendData/AddSubdirectory"
    dMaskSchema["2"] = "WriteData/AddFile"
    dMaskSchema["1"] = "ReadData/ListDirectory"

    iRemainder = iDec

    # iterate through mask
    for schemaItemKey in dMaskSchema:
        # attempt = int(iRemainder) - int(schemaItemKey)

        if int(schemaItemKey) <= int(iRemainder):
            sOutputMask.append(dMaskSchema[schemaItemKey])
            iRemainder = int(iRemainder) - int(schemaItemKey)

    return sOutputMask

def winevt4663mask(argQuery):
    lResult = translateMask(argQuery)

    i = 0
    strConcat = ""

    for item in lResult:
        if i > 0:
            strConcat = strConcat + ", "
        strConcat = strConcat + item
        i = i + 1
    
    return {"value": strConcat}

def virus_total_hash(arg_query):
    rs_json = query_virus_total(arg_query, "files")
    return {
        "value": rs_json,
        "lookup": str(arg_query)
    }

def convert_comma_string_to_list(comma_list: str):
    new_list = []
    for item in comma_list.split(","):
        x = item.replace("[", "")
        x = x.replace("]", "")
        x = x.strip()
        new_list.append(x)
    return new_list

def cache_dns_answer(arg_query):
    o_js = {}
    try:
        str_url_decode = urllib.parse.unquote(arg_query)
        o_js = json.loads(str_url_decode) # dict
    except Exception as e:
        excpInfo = "" + str(e) + "; Query: " + str(arg_query)
        dicRet = {}
        dicRet["err"] = excpInfo
        logging.error(excpInfo)

    if len(o_js) < 1:
        logging.error("[[cache_dns_answer]] JSON could not be parsed")
        return {"value":""}
    
    if not "query" in o_js:
        logging.error("[[cache_dns_answer]] missing key 'query' in parsed JSON")
        return {"value":""}
    
    if not "answer" in o_js:
        logging.error("[[cache_dns_answer]] missing key 'answer' in parsed JSON")
        return {"value":""}

    s_query = o_js['query']
    l_answer = o_js['answer']

    if type(l_answer) == str:
        logging.warn("incorrect type for answer!")
        l_answer = convert_comma_string_to_list(l_answer)

    logging.debug("s_query: " + str(s_query) + " (" + str(type(s_query)) + ")")
    logging.debug("l_answer: " + str(l_answer) + " (" + str(type(l_answer)) + ")")

    if type(l_answer) == list:
        for one_answer in l_answer:
            logging.debug("Answer: " + str(one_answer))
            b_is_ip = validate_ip_addr_ver(str(one_answer), 4)
            
            logging.debug("     b_is_ip: " + str(b_is_ip))
            if b_is_ip == True:
                dict_to_cache = {
                    "ip": str(one_answer),
                    "name": str(s_query),
                    "has_lookup": 1,
                    "lookup_source": "zeek",
                    "ttl": 604800,
                    "date_created": getUnixTimeUtc()
                }
                logging.debug(dict_to_cache)
                delete_lookup_in_cache("rdns", str(one_answer))
                save_lookup_in_cache("rdns", dict_to_cache)
                logging.info("[[cache_dns_answer]] caching query and answer from zeek DNS logging. " + str(one_answer) + "=" + str(s_query))

    return {"value":""}

def parseArgs(argQuery):
    dictArgs = {}
    sKey = ""
    sVal = ""

    oSplit = argQuery.split("&")
    for sArg in oSplit:
        # print(sArg)
        oKv = sArg.split("=")
        sKey = oKv[0]
        sVal = oKv[1]
        dictArgs[sKey] = sVal
    return dictArgs

def doLookups(argQuery):
    oArgs = parseArgs(argQuery)
    sLookup = oArgs['lookup']
    if sLookup == "rdns":
        return lookupRDns(oArgs['key'])
    elif sLookup == "dns":
        return lookupDns(oArgs['key'])
    elif sLookup == "anom_url":
        return anomUrl(argQuery)
    elif sLookup == "4663mask":
        return winevt4663mask(oArgs['key'])
    elif sLookup == "vt_hash":
        return virus_total_hash(oArgs['key'])
    elif sLookup == "cache_dns_answer":
        return cache_dns_answer(oArgs['key'])

def log_level_from_string(log_level: str):
    if log_level.upper() == "DEBUG":
        return logging.DEBUG
    elif log_level.upper() == "INFO":
        return logging.INFO
    elif log_level.upper() == "WARN":
        return logging.WARN
    elif log_level.upper() == "ERROR":
        return logging.ERROR
    elif log_level.upper() == "CRITICAL":
        return logging.CRITICAL

    return logging.INFO

# logging.basicConfig(
#         filename=logFile,
#         encoding='utf-8',
#         level=logging.DEBUG,
#         format='%(asctime)s %(levelname)-8s %(message)s',
#         datefmt='%Y-%m-%d %H:%M:%S'
#     )




# handlers
logging_file_handler = logging.FileHandler(logFile)
logging_file_handler.setLevel(log_level_from_string(str(args.log_level)))
formatter = logging.Formatter('%(asctime)s.%(msecs)03d %(levelname)-8s (' + str(hostName) + ':' + str(serverPort) + ') %(message)s', '%Y-%m-%d %H:%M:%S')
logging_file_handler.setFormatter(formatter)
logger.addHandler(logging_file_handler)

logging_console_handler = colorlog.StreamHandler()
logging_console_handler.setLevel(log_level_from_string(str(args.console_level)))
formatter = ColoredFormatter(
        '%(asctime)s.%(msecs)03d %(log_color)s%(levelname)-8s%(reset)s (' + str(hostName) + ':' + str(serverPort) + ') %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S',
        reset=True,
        log_colors={
            "DEBUG": "cyan",
            "INFO": "green",
            "WARNING": "yellow",
            "ERROR": "red",
            "CRITICAL": "red",
        },
    )
logging_console_handler.setFormatter(formatter)
logger.addHandler(logging_console_handler)

# alias so we don't break existing logging
logging = logger

class MyServer(BaseHTTPRequestHandler):
    def setup(self):
        BaseHTTPRequestHandler.setup(self)
        self.request.settimeout(5)

    def myLog( self, fmt, request, code, other ):
        # syslog( LOG_INFO, '%s %s' % ( code, request) )
        logging.info('[[HTTP]] %s %s' % ( code, request))

    def do_GET(self):
        http_write_output = ""
        self.log_message = self.myLog

        # time.sleep(5)
        
        # self.wfile.write(bytes("%s" % self.path, "utf-8"))
        o = urlparse(self.path)
        if o.path == "/":
            dictRs = {}

            # todo
            # 
            #   add caching (not sure what exactly) in the event we get an empty value or error
            #       from source, we can use last known good value.
            # 
            #   Additional functionality, possible long-term caching DNS results
            #       and having a scheduler periodically validating the cache, keeping it fresh
            #       goal is to improve throughput of DNS lookups

            try:
                # logging.debug("Lookup Query: " + str(o.query))
                rs = doLookups(o.query)

                if "exception" in rs:
                    self.send_response(500)
                    excpInfo = "" + str(rs['exception']) + "; Query: " + str(o.query)
                    # dicRet = {}
                    # dicRet["err"] = excpInfo
                    logging.error(excpInfo)
                    
                    dictRs['value'] = ""
                else:
                    if rs['value'] == "":
                        self.send_response(404)
                    else:
                        self.send_response(200)
                        if args.log_response == True:
                            input_args_for_logging = parseArgs(o.query)
                            log_dict = {
                                "lookup": input_args_for_logging['lookup'],
                                "key": input_args_for_logging['key'],
                                "result": rs['value']
                            }
                            logging.info(log_dict)
                    if "cached" in rs:
                        if rs['cached'] == 1:
                            logging.info("[[do_GET]] Cached=1, " + rs['meta'] + ", " + rs['lookup'] + "=" + rs['value'])
                    dictRs['value'] = rs['value']
                
                y = json.dumps(dictRs)
                http_write_output = y

            except Exception as e:
                self.send_response(400)
                excpInfo = "" + str(e) + "; Query: " + str(o.query)
                dicRet = {}
                dicRet["err"] = excpInfo
                logging.error(excpInfo)
        elif o.path == "/favicon.ico":
            http_write_output = ""
            self.send_response(200)
        else:
            self.send_response(404)

        self.send_header("Content-type", "application/json")
        self.end_headers()
        if http_write_output:
            logging.debug("Lookup Answer: " + str(http_write_output))

        self.wfile.write(bytes(http_write_output, "utf-8"))
        return
       
class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    pass

if configFromArg['exit']:
    rs = doLookups("lookup=" + configFromArg['lookup'] + "&key=" + configFromArg['key'])
    print(rs)
else:
    if __name__ == "__main__":
        
        # initDb(sDbFileName)
        init_db_success = init_cache_db(mariadb_host, mariadb_port, mariadb_user, mariadb_pass)
        if init_db_success == False:
            logging.error("ERROR! Failed to initialize graylog_lookups MariaDB database.")
            if args.cache_mariadb == True:
                logging.critical("--cache-mariadb=true , cannot continue.")
                exit(1)

        # webServer = HTTPServer((hostName, serverPort), MyServer)
        webServer = ThreadingHTTPServer((hostName, serverPort), MyServer)
        logging.info("Server started http://%s:%s" % (hostName, serverPort))

        try:
            webServer.serve_forever()
        except KeyboardInterrupt:
            pass

        webServer.server_close()
        logging.info("Server stopped.")