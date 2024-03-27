import requests
import datetime
from urllib.parse import urlparse
from .endpoints import Endpoints
from urllib import parse
import json
import jsonpath_ng.ext as jp

class py_graylog_api:
    # Class currently only supports the GET methods that don't insert values into the url and return a JSON object.
    # TODO: Extend to support POST, PUT, & DELETE methods.
    def __init__(self, graylog_server_url, api_url, access_token):

        url = parse.urljoin(graylog_server_url, api_url)

        self.url = url
        self._endpoint = urlparse(self.url).path
        self._access_token = (access_token, "token")
        self.methods = {
            "get": self._get,
            "post": self._post,
            "put": self._put,
            "delete": self._delete
        }

    def mergeDict(dictOrig: dict, dictToAdd: dict, allowReplacements: bool):
        for item in dictToAdd:
            
            bSet = True
            if item in dictOrig:
                if allowReplacements == False:
                    bSet = False
            
            if bSet == True:
                dictOrig[item] = dictToAdd[item]
        
        return dictOrig


    def _get(self, **kwargs):
        h = {'Accept': 'application/json'}
        response = requests.get(self.url, auth=self._access_token, headers=h, params=kwargs)
        return response

    def _post(self, **kwargs):
        # TODO: Implement
        # sHeaders = {"Accept":"application/json", "X-Requested-By":"python"}
        # raise NotImplementedError("POST: Not Yet Implemented")
        h = {'Accept': 'application/json', "X-Requested-By":"py_graylog_api"}

        args_for_req = {}
        args_for_req["url"] = self.url
        args_for_req["headers"] = h
        args_for_req["auth"] = auth=self._access_token
        for item in kwargs:
            args_for_req[item] = kwargs[item]

        # print(self.url)

        response = requests.post(**args_for_req)

        return response

    def _put(self, **kwargs):
        # TODO: Implement
        # sHeaders = {"Accept":"application/json", "X-Requested-By":"python"}
        raise NotImplementedError("PUT: Not Yet Implemented")

    def _delete(self, **kwargs):
        # TODO: Implement
        # sHeaders = {"Accept":"application/json", "X-Requested-By":"python"}
        raise NotImplementedError("DELETE: Not Yet Implemented")

    def _methods(self, method):
        # Gets a pointer to the right function depending on API access method
        if method not in self.methods.keys():
            raise ValueError("\"{0}\" is not a supported method. " +
                             "Please use one of the following: {1}".format(method, self.methods.keys()))
        return self.methods[method]

    def send(self, method, **kwargs):
        endpoints = Endpoints()
        keys = kwargs.keys()
        
        endpoints.check(keys, self._endpoint)

        if "variable_expansion" in kwargs:
            for replacement in kwargs["variable_expansion"]:
                self.url = self.url.replace(replacement, kwargs["variable_expansion"][replacement])
            del kwargs["variable_expansion"]

        return self._methods(method.lower())(**kwargs)
    
    def parse_options(self, dict_options: dict):
        expected_return_code = 0

        if "expected" in dict_options:
            if "return_code" in dict_options["expected"]:
                expected_return_code = dict_options["expected"]["return_code"]

        return {
            "expected_return_code": expected_return_code
        }

    def send_safe(self, method, **kwargs):
        if "options" in kwargs:
            d_options = kwargs["options"]
            parsed_options = self.parse_options(d_options)
            del kwargs["options"]
        else:
            parsed_options = self.parse_options({})

        response = self.send(method, **kwargs)
        # headers
        # json()
        # ok
        # reason
        # status_code
        # text
        # url

        # print(response.json())

        # if int(parsed_options["expected_return_code"]) > 0 and int(response.status_code) != int(parsed_options["expected_return_code"]):
        
        return response

    def views_search(s_graylog_server: str, s_token: str, my_params):
        if not "query" in my_params:
            raise ValueError("my_params must have a 'query' parameter.")
        if not "timerange" in my_params:
            raise ValueError("my_params must have a 'timerange' parameter.")
        if not "search_type" in my_params:
            raise ValueError("my_params must have a 'search_type' parameter.")
        if not "type" in my_params["search_type"]:
            raise ValueError('my_params["search_type"] must have a "type" parameter.')

        # =====================================================================
        # Execute Search
        s_api_url = "/api/views/search"
        api = py_graylog_api(s_graylog_server, s_api_url, s_token)
        
        # str_query = '_exists_:destination_ip AND NOT _exists_:destination_ip_dns AND destination_ip:"0.0.0.0/0" AND NOT destination_ip:"172.16.0.0/12" AND NOT destination_ip:"10.0.0.0/8" AND NOT destination_ip:"192.168.0.0/16" AND NOT destination_ip:255.255.255.255 AND NOT destination_ip:239.255.255.250 AND NOT destination_ip:224.0.0.252 AND _exists_:destination_ip_as_number'
        str_query = my_params['query']



        oPayload = {}
        oQuery = {}
        
        oQuery["query"] = {"type": "elasticsearch", "query_string": str_query}

        if "streams" in my_params:
            l_stream_filters = []

            streams_list = my_params["streams"].split(",")
            for stream_id in streams_list:
                l_stream_filters.append({"type": "stream", "id": stream_id})

            oQuery["filter"] = {
                "type": "or",
                "filters": l_stream_filters
            }

        oQuery["timerange"] = {"from": int(my_params["timerange"]), "type": "relative"}
        
        oQuerySearchTypes = {}
        if my_params["search_type"]["type"] == "aggregation":
            oQuerySearchTypes = {
                "name": "chart",
                "series": [
                    {"id": "count()", "type": "count"}
                ],
                "rollup": False,
                "row_groups": [
                    {"type": "values", "field": my_params["search_type"]["field"], "limit": int(my_params["search_type"]["limit"])}
                ],
                "type": "pivot"
            }
        
        oQuery["search_types"] = [oQuerySearchTypes]
        
        oPayload["queries"] = [oQuery]
        # print(json.dumps(oPayload, indent=4))
        # exit()

        kwargs = {
            "json": oPayload
        }
        response = api.send("post", **kwargs)

        b_continue = True
        if not response.ok:
            b_continue = False
            return response
        # print(json.dumps(response.json(), indent=4))

        if not "id" in response.json():
            return response
        
        search_id = response.json()["id"]

        # =====================================================================
        # Retrieve result
        # s_api_url = "".join([ "/api/views/search/", search_id, "/execute" ])
        s_api_url = "".join([ "/api/views/search/<search_id>/execute" ])
        api = py_graylog_api(s_graylog_server, s_api_url, s_token)
        kwargs = {
            "json": {
                "parameter_bindings": {}
            },
            "variable_expansion": {
                "<search_id>": search_id
            }
        }
        response = api.send("post", **kwargs)
        # print(json.dumps(response.json(), indent=4))

        if not "jsonpath" in my_params:
            return response.json()
        else:
            formatted_response = api.formatters(response, "jsonpath", my_params["jsonpath"])
            # print(json.dumps(formatted_response, indent=4))
            return formatted_response

    def formatters(self, response, format: str, format_extra: str):
        if not response:
            return False

        if format.lower() == "jsonpath":
            query = jp.parse(format_extra)
            output = []
            for match in query.find(response.json()):
                output.append(match.value)
            return output
        elif format.lower() == "first_non_empty_from_multi_column_list":
            # assumes input us from api.formatters(response, "jsonpath", "datarows[*]")
            l_output = []
            for child_list in response:
                for entry in child_list:
                    if type(entry) == str:
                        # print("".join(["Type: ", str(type(entry)), ": ", str(entry)]))
                        if not entry.lower() == "(empty value)":
                            return entry