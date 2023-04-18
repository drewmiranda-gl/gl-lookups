from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import result
from urllib.parse import urlparse
import urllib.parse
# import time
import json
import argparse
# import sys
import logging
import ipaddress
import sqlite3
from os.path import exists

# defaults
parser = argparse.ArgumentParser(description="Just an example",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--port", help="Port to bind to (TCP)", default="8080")
parser.add_argument("--log", help="Output Log File", default="web.log")
parser.add_argument('--exit', action=argparse.BooleanOptionalAction)
parser.add_argument("--lookup")
parser.add_argument("--key")
parser.add_argument('--verbose', action=argparse.BooleanOptionalAction)
parser.add_argument('--debug', action=argparse.BooleanOptionalAction, default=False)
parser.add_argument('--ignore_sqlite', action=argparse.BooleanOptionalAction)
parser.add_argument("--db", help="Sqlite DB File", default="searches.db")

args = parser.parse_args()
configFromArg = vars(args)

hostName = "localhost"
serverPort = int(configFromArg['port'])
logFile = str(configFromArg['log'])
sDbFileName = args.db

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

def lookupRDns(argQuery):
    # log to filter out/ignore
    #   255.255.255.255
    #   private IP
    #       127.0.0.0/8 (127.0.0.0 - 127.255.255.255)
    #       10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    #       127.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    #       192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
    #   multicast/broadcast

    # Check sql lite database
    if configFromArg['ignore_sqlite'] == True:
        dbRs = []
    else:
        dbRs = getDbRow(sDbFileName, "SELECT * FROM rdns WHERE ip = '" + str(argQuery) + "'")
        
    # if IP is found
    if len(dbRs) > 0:
        if configFromArg['verbose'] == True:
            print(json.dumps(dbRs))

        # check for TTL expiration
        unix_time_now_utc = getUnixTimeUtc()
        ttl = dbRs['ttl']
        date_created = dbRs['date_created']
        if date_created + ttl < unix_time_now_utc:
            print("TTL has expired!")
            # delete record
            deleteIp(sDbFileName, argQuery)
        else:
            if dbRs['has_lookup'] == False:
                if configFromArg['verbose'] == True:
                    print("Entry found in SQLite rDNS table, but no hostname saved. Returning Empty.")
                # return empty if no lookup is present, this will prevent this IP from
                #   causing a rDNS query timeout
                return {"value": ""}
            else:
                if configFromArg['verbose'] == True:
                    print("Entry found in SQLite rDNS table. Returning cached hostname.")
                # if a lookup exists in local sqlite, return that
                return {
                    "value": dbRs['name'],
                    "lookup": argQuery,
                    "meta": "Returned via sqlite cache",
                    "cached": 1
                }
    else:
        if configFromArg['verbose'] == True:
            print("NO Entry found in SQLite rDNS table.")


    lIgnoreThese = ["239.255.255.250", "255.255.255.255"]

    bGiveResult = True

    if str(argQuery) in lIgnoreThese:
        bGiveResult = False
    elif ipaddress.ip_address(str(argQuery)) in ipaddress.ip_network('192.168.0.0/16'):
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

        if "exception" in result:
            # if configFromArg['verbose'] == True:
            #     print("exeption is in result")
            # add to db for future exclusion
            addTimeoutIp(sDbFileName, argQuery, '')
            return result
        else:
            addTimeoutIp(sDbFileName, argQuery, result)

        return {
            "value": result,
            "meta": "returned from rDNS query",
            "cached": 0
        }

def lookupDns(argQuery):
    result = get_ipv4_by_hostname(argQuery)
    return result
    # return result

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

class MyServer(BaseHTTPRequestHandler):
    def setup(self):
        BaseHTTPRequestHandler.setup(self)
        self.request.settimeout(5)

    def myLog( self, fmt, request, code, other ):
        logging.basicConfig(filename=logFile, encoding='utf-8', level=logging.DEBUG)
        # syslog( LOG_INFO, '%s %s' % ( code, request) )
        logging.info('%s %s' % ( code, request))

    def do_GET(self):
        http_write_output = ""
        self.log_message = self.myLog

        
        
        
        
        # self.wfile.write(bytes("%s" % self.path, "utf-8"))
        # print(self.path)
        o = urlparse(self.path)
        if o.path == "/":
            dictRs = {}
            # print("path is / lets do cool stuff")

            # todo
            # 
            #   add caching (not sure what exactly) in the event we get an empty value or error
            #       from source, we can use last known good value.
            # 
            #   Additional functionality, possible long-term caching DNS results
            #       and having a scheduler periodically validating the cache, keeping it fresh
            #       goal is to improve throughput of DNS lookups

            try:
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
                    
                    if "cached" in rs:
                        if rs['cached'] == 1:
                            logging.info("Cached=1, " + rs['meta'] + ", " + rs['lookup'] + "=" + rs['value'])
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
        self.wfile.write(bytes(http_write_output, "utf-8"))

if configFromArg['exit']:
    rs = doLookups("lookup=" + configFromArg['lookup'] + "&key=" + configFromArg['key'])
    print(rs)
else:
    if __name__ == "__main__":
        initDb(sDbFileName)
        webServer = HTTPServer((hostName, serverPort), MyServer)
        print("Server started http://%s:%s" % (hostName, serverPort))

        try:
            webServer.serve_forever()
        except KeyboardInterrupt:
            pass

        webServer.server_close()
        print("Server stopped.")