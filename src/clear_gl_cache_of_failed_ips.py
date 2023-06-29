import requests
from requests.auth import HTTPBasicAuth
import configparser
import json
import glob
import argparse
import re
import sqlite3
from os.path import exists
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# defaults
parser = argparse.ArgumentParser(description="Just an example",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--debug", "-d", help="For debugging", action=argparse.BooleanOptionalAction)
parser.add_argument("--config", help="Config Filename", default="config.ini")
parser.add_argument("--verbose", help="Verbose output.", action=argparse.BooleanOptionalAction, default=False)

args = parser.parse_args()
configFromArg = vars(args)

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

print("Script START - clear_gl_cache_of_failed_ips")

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

def queryGraylog():
    print(alertText + "Searching Graylog" + defText)
    sResult = ""
    list_rs = []

    sUrl = sArgBuildUri + "/api/views/search"
    
    sHeaders = {"Accept":"application/json", "X-Requested-By":"python"}

    # oJson = {"parameters":{},"comment":""}
    oPayload = {}
    oQuery = {}

    oQuery["filter"] = {
        "type": "or",
        "filters": [
            {
            "type": "stream",
            "id": "633b3c3267151134502f72b2"
            }
        ]
    }
    oQuery["query"] = {"type": "elasticsearch", "query_string": "NOT hap_http_resp_code:200 AND NOT hap_http_resp_code:404 AND hap_time_srv_resp_ms:\"-1\""}
    oQuery["timerange"] = {"from": 7200, "type": "relative"}
    
    oQuerySearchTypes = {"name": "chart", "series": [{"id": "count()", "type": "count"}], "rollup": False, "row_groups": [{"type": "values", "field": "hap_http_req_key", "limit": 15}], "type": "pivot"}
    oQuery["search_types"] = [oQuerySearchTypes]
    
    oPayload["queries"] = [oQuery]

    print("posting search query paylod...")
    r = requests.post(sUrl, json = oPayload, headers=sHeaders, verify=False, auth=HTTPBasicAuth(sArgUser, sArgPw))
    
    if configFromArg['verbose']:
        print(r.status_code)
        print(r.headers)
        print(r.text)

    oRespJson = json.loads(r.text)
    sSearchId = oRespJson['id']
    print("Obtained search id: " + sSearchId)
    
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
                    for row in lRows:
                        if 'key' in row:
                            sResult = row['key'][0]
                            # print(sResult)
                            if len(sResult):
                                list_rs.append(sResult)
    
    return list_rs

def delete_key_value_from_graylog_cache(cache_oid: str, cache_key: str):
    # print("Clearing from cache oid " + cache_oid + ", key: " + cache_key)
    sHeaders = {"Accept":"application/json", "X-Requested-By":"python"}
    sUrl = sArgBuildUri + "/api/cluster/system/lookup/tables/" + cache_oid + "/purge?key=" + cache_key
    r = requests.post(sUrl, json = False, headers=sHeaders, verify=False, auth=HTTPBasicAuth(sArgUser, sArgPw))
    if configFromArg['verbose']:
        print(r.status_code)
        print(r.headers)
        print(r.text)
    
    if r.status_code == 200:
        rs_json = json.loads(r.text)
        for child_rs_json in rs_json:
            use_for_rs_json = child_rs_json

        if use_for_rs_json in rs_json:
            if "response" in rs_json[use_for_rs_json]:
                if "success" in rs_json[use_for_rs_json]['response']:
                    if rs_json[use_for_rs_json]['response']["success"] == True:
                        addt_text_code = ""
                        if "code" in rs_json[use_for_rs_json]['response']:
                            addt_text_code = " (graylog api return code: " + str(rs_json[use_for_rs_json]['response']["code"]) + ")"
                        print(successText + "Successfully cleared key: " + defText + cache_key + successText + " from cache oid " + cache_oid + defText + addt_text_code)
                        return True
    
    print(errorText + "Failed to clear key: " + cache_key + " from cache oid " + cache_oid + defText + " (status_code: " + str(r.status_code) + ")")
    return False


ipsFound = queryGraylog()
for ip_addr in ipsFound:
    delete_key_value_from_graylog_cache("633b3a7f67151134502f6e35", ip_addr)

print("Script END - clear_gl_cache_of_failed_ips")
print(defText)
