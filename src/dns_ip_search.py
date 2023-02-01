import requests
from requests.auth import HTTPBasicAuth
import configparser
import json
import glob
import argparse
import re
import sqlite3
from os.path import exists

# defaults
parser = argparse.ArgumentParser(description="Just an example",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--debug", "-d", help="For debugging", action=argparse.BooleanOptionalAction)
parser.add_argument("--config", help="Config Filename", default="config.ini")
parser.add_argument("--verbose", help="Verbose output.", action=argparse.BooleanOptionalAction, default=False)

args = parser.parse_args()
configFromArg = vars(args)

sDbFileName = "/opt/graylog/lookup-service/searches.db"

# font
#           Style
#           v Color
#           v v  Background
#           v v  v
defText = "\033[0;30;50m"
alertText = "\033[1;33;50m"
errorText = "\033[1;31;50m"
successText = "\033[1;32;50m"

print(defText)

# Colors
# 
# Example
# Text Style;Color;Background
# 
# Text Style
#   No Effect   0
#   Bold        1
#   Underline   2
#   Negative1   3
#   Negative2   5
# 
# Color
#   Black       30
#   Red         31
#   Green       32
#   Yellow      33
#   Blue        34
#   Purple      35
#   Cyan        36
#   White       37
# 
# Backgrounds
#   Black       40
#   Red         41
#   Green       42
#   Yellow      43
#   Blue        44
#   Purple      45
#   Cyan        46
#   White       47

print("Arguments: ")
print(configFromArg)
print("")

sAuthFile = configFromArg['config']

if configFromArg['debug']:
    print("DEBUG ENABLED")
    print("")

# load config file for server info, auth info
config = configparser.ConfigParser()
config.read(sAuthFile)

# build URI
sArgBuildUri = ""
sArgHttps = config['DEFAULT']['https']
if sArgHttps == "true":
    sArgBuildUri = "https://"
else:
    sArgBuildUri = "http://"

sArgHost = config['DEFAULT']['host']
sArgPort = config['DEFAULT']['port']
sArgUser = config['DEFAULT']['user']
sArgPw = config['DEFAULT']['password']

# print("Graylog Server: " + sArgHost)
print(alertText + "Graylog Server: " + sArgHost + defText + "\n")

# build server:host and concat with URI
sArgBuildUri=sArgBuildUri+sArgHost+":"+sArgPort

def queryGraylog(strArgIp):
    print(alertText + "Searching Graylog " + defText + " for ip '" + strArgIp + "'" + defText)
    sResult = ""

    sUrl = sArgBuildUri + "/api/views/search"
    
    sHeaders = {"Accept":"application/json", "X-Requested-By":"python"}

    # oJson = {"parameters":{},"comment":""}
    oPayload = {}
    oQuery = {}
    oQuery["query"] = {"type": "elasticsearch", "query_string": "\"" + str(strArgIp) + "\" AND _exists_:pf_syslog_js_query"}
    oQuery["timerange"] = {"from": 86400, "type": "relative"}
    
    oQuerySearchTypes = {"name": "chart", "series": [{"id": "count()", "type": "count"}], "rollup": False, "row_groups": [{"type": "values", "field": "pf_syslog_js_query", "limit": 15}], "type": "pivot"}
    oQuery["search_types"] = [oQuerySearchTypes]
    
    oPayload["queries"] = [oQuery]

    r = requests.post(sUrl, json = oPayload, headers=sHeaders, verify=False, auth=HTTPBasicAuth(sArgUser, sArgPw))
    
    if configFromArg['verbose']:
        print(r.status_code)
        print(r.headers)
        print(r.text)

    oRespJson = json.loads(r.text)
    sSearchId = oRespJson['id']
    
    sUrl = sArgBuildUri + "/api/views/search/" + str(sSearchId) + "/execute"
    oJsonExecute = {"parameter_bindings":{}}
    r = requests.post(sUrl, json = oJsonExecute, headers=sHeaders, verify=False, auth=HTTPBasicAuth(sArgUser, sArgPw))
    if configFromArg['verbose']:
        print(r.status_code)
        print(r.headers)
        print(r.text)

    oSearchRsJson = json.loads(r.text)
    oRs = oSearchRsJson['results']
    for oSearchResult in oRs:
        oResultInResult = oRs[oSearchResult]['search_types']
        for oFinalResultGuid in oResultInResult:
            if 'rows' in oRs[oSearchResult]['search_types'][oFinalResultGuid]:
                lRows = oRs[oSearchResult]['search_types'][oFinalResultGuid]['rows']
                if len(lRows) > 0:
                    if 'key' in lRows[0]:
                        sResult = lRows[0]['key'][0]
    
    return sResult

def getDbCur(sArgDbFile):
    con = sqlite3.connect(sArgDbFile)
    cur = con.cursor()
    return {"con": con, "cur": cur}

def dbCreateTable(sArgDbFile):
    cur = getDbCur(sArgDbFile)['cur']
    try:
        cur.execute('CREATE TABLE "rdns" ("ip" TEXT,"name" TEXT,"has_lookup" INTEGER DEFAULT 0);')
    except:
        print(errorText + "ERROR, failed to create table `rdns`" + defText)

def initDb(sArgDbFile):
    if exists(sArgDbFile):
        cur = getDbCur(sArgDbFile)['cur']
        # cur.execute("CREATE TABLE rdns(ip, name)")
        try:
            res = cur.execute("SELECT * FROM rdns")
            iCount = 0
            for row in res:
                iCount = iCount + 1
                break
            
            if iCount < 1:
                dbCreateTable(sArgDbFile)
        except:
            dbCreateTable(sArgDbFile)
        
    else:
        print(alertText + "DB file doesnt exist, creating" + defText)
        dbCreateTable(sArgDbFile)

def commitToDb(sArgDbFile, sArgIp, sArgName):
    oDb = getDbCur(sArgDbFile)
    cur = oDb['cur']
    con = oDb['con']

    # does exist?
    res = cur.execute("SELECT * FROM rdns WHERE ip = '" + str(sArgIp) + "'")
    bExists = False
    for row in res:
        bExists = True
        break

    if bExists == False:
        # Insert, does not already exist
        try:
            sSqlExec = "INSERT INTO rdns VALUES ('" + str(sArgIp) + "', '" + str(sArgName) + "')"
            cur.execute(sSqlExec)
            con.commit()
            print(successText + "Inserted name '" + str(sArgName) + "' for ip '" + str(sArgIp) + "'" + defText)
        except:
            print(errorText + "ERROR, failed insert dns name '" + str(sArgName) + "' for ip '" + str(sArgIp) + "'" + defText)
        
    else:
        # exists, update
        try:
            sSqlExec = "UPDATE rdns SET name = '" + str(sArgName) + "' WHERE ip = '" + str(sArgIp) + "'"
            cur.execute(sSqlExec)
            con.commit()
            print(successText + "Updated name '" + str(sArgName) + "' for ip '" + str(sArgIp) + "'" + defText)
        except:
            print(errorText + "ERROR, failed update dns name '" + str(sArgName) + "' for ip '" + str(sArgIp) + "'" + defText)

def parentIpSniff(sDbFileName, sArgIp):
    ipLookupFound = queryGraylog(sArgIp)
    if len(ipLookupFound) > 0:
        commitToDb(sDbFileName, sArgIp, ipLookupFound)
    else:
        print(alertText + "No search result found for ip '" + str(sArgIp) + "'")

def get_domain_name(ip_address):
    import socket
    socket.setdefaulttimeout(5)

    try:
        result=socket.gethostbyaddr(ip_address)
        result = list(result)[0]
    except Exception as e:
        result = None

    return result

def lookupRDns(argQuery):
    result = get_domain_name(argQuery)
    return result

def getRows(sArgDbFile, strSql):
    lRs = []

    lSchema = ['ip', 'name', 'has_lookup']

    i = 0
    d = {}

    if exists(sArgDbFile):
        cur = getDbCur(sArgDbFile)['cur']
        try:
            cur.execute(strSql)
            rows = cur.fetchall()
            for row in rows:
                i = 0
                d = {}
                print("")
                for schemaItem in lSchema:
                    # print(schemaItem + ": " + str(row[i]))
                    d[schemaItem] = row[i]
                    i = i +1
                lRs.append(d)
            
            return lRs
        
        except:
            print(alertText + "ERROR returning rows.")
            return {}

def updateRow(sArgDbFile, strSql):
    oDb = getDbCur(sArgDbFile)
    cur = oDb['cur']
    con = oDb['con']
    try:
        sSqlExec = strSql
        cur.execute(sSqlExec)
        con.commit()
        print(successText + "Updated: '" + strSql + "'" + defText)
    except:
        print(errorText + "ERROR, failed update: '" + strSql + defText)


# will collect IPs from a text file written from output of web.py when an IP has no result
# iterate through list saving results found in graylog search
# this can run on a schedule via cronjob to find hosts that may return an IP but don't have valid rdns/ptr record

rows = getRows(sDbFileName, "SELECT * FROM rdns")
for row in rows:
    # dns query
    print("rDNS lookup for " + row['ip'])
    
    dns_rs = lookupRDns(row['ip'])
    # dns_rs = None
    
    bDnsFound = False
    if dns_rs:
        if len(dns_rs) > 0:
            # if valid DNS result
            # UPDATE record
            bDnsFound = True
    
    if bDnsFound == True:
        updateRow(sDbFileName, "UPDATE rdns SET name = '" + str(dns_rs) + "', has_lookup = 1 WHERE ip = '" + str(row['ip']) + "'")
    else:
        print(alertText + "NO DNS found, attempting Graylog Log Lookup: " + row['ip'])
        ipLookupFound = queryGraylog(row['ip'])
        bGraylogDnsLogFound = False
        if ipLookupFound:
            if len(ipLookupFound) > 0:
                # if valid DNS result
                # UPDATE record
                bGraylogDnsLogFound = True
        
        if bGraylogDnsLogFound == True:
            updateRow(sDbFileName, "UPDATE rdns SET name = '" + str(ipLookupFound) + "', has_lookup = 1 WHERE ip = '" + str(row['ip']) + "'")
        else:
            print(alertText + "No Graylog Log Lookup found: " + row['ip'] + defText)

# parentIpSniff(sDbFileName, "104.18.28.25")
print(defText)
