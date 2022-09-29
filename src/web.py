from http.server import BaseHTTPRequestHandler, HTTPServer
from unittest import result
from urllib.parse import urlparse
import time
import json

hostName = "localhost"
serverPort = 8080

def get_ipv4_by_hostname(hostname):
    import socket
    rs = socket.gethostbyname(hostname)
    return rs

def get_domain_name(ip_address):
  import socket
  result=socket.gethostbyaddr(ip_address)
  return list(result)[0]

def lookupRDns(argQuery):
    result = get_domain_name(argQuery)
    return result

def lookupDns(argQuery):
    result = get_ipv4_by_hostname(argQuery)
    return result
    # return result

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

class MyServer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.end_headers()
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

            rs = doLookups(o.query)
            dictRs['value'] = rs
            y = json.dumps(dictRs)

            self.wfile.write(bytes(y, "utf-8"))

if __name__ == "__main__":        
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print("Server started http://%s:%s" % (hostName, serverPort))

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    print("Server stopped.")
