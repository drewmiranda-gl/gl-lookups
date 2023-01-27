from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import result
from urllib.parse import urlparse
# import time
import json
import argparse
# import sys
import logging
import ipaddress

# defaults
parser = argparse.ArgumentParser(description="Just an example",
                                 formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("--port", help="Port to bind to (TCP)", default="8080")
parser.add_argument("--log", help="Output Log File", default="web.log")


args = parser.parse_args()
configFromArg = vars(args)

hostName = "localhost"
serverPort = int(configFromArg['port'])
logFile = str(configFromArg['log'])

def get_ipv4_by_hostname(hostname):
    import socket
    rs = socket.gethostbyname(hostname)
    return rs

def get_domain_name(ip_address):
  import socket
  result=socket.gethostbyaddr(ip_address)
  return list(result)[0]

def lookupRDns(argQuery):
    # log to filter out/ignore
    #   255.255.255.255
    #   private IP
    #       127.0.0.0/8 (127.0.0.0 - 127.255.255.255)
    #       10.0.0.0/8 (10.0.0.0 - 10.255.255.255)
    #       127.16.0.0/12 (172.16.0.0 - 172.31.255.255)
    #       192.168.0.0/16 (192.168.0.0 - 192.168.255.255)
    #   multicast/broadcast

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
        return ""
    else:
        result = get_domain_name(argQuery)
        return result

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

    for schemaItemKey in dMaskSchema:
        attempt = int(iRemainder) - int(schemaItemKey)
        # print("")
        # print("Attempt: " + str(attempt))
        if attempt > 0:
            sOutputMask.append(dMaskSchema[schemaItemKey])
            iRemainder = int(iRemainder) - int(schemaItemKey)
            # print("iRemainder: " + str(iRemainder))

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
    
    return strConcat

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
    def myLog( self, fmt, request, code, other ):
        logging.basicConfig(filename=logFile, encoding='utf-8', level=logging.DEBUG)
        # syslog( LOG_INFO, '%s %s' % ( code, request) )
        logging.info('%s %s' % ( code, request))

    def do_GET(self):
        self.log_message = self.myLog

        # self.send_response(200)
        # self.send_header("Content-type", "application/json")
        # self.end_headers()
        
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

            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()

            try:
                rs = doLookups(o.query)
                dictRs['value'] = rs
                y = json.dumps(dictRs)
                self.wfile.write(bytes(y, "utf-8"))
            except Exception as e:
                excpInfo = "" + str(e) + "; Query: " + str(o.query)
                dicRet = {}
                dicRet["err"] = excpInfo
                # self.wfile.write(bytes(json.dumps(dicRet), "utf-8"))
                # print(excpInfo)
                logging.error(excpInfo)

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
