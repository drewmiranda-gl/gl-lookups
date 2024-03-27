

class Endpoints:
    # This class contains a list of the REQUIRED keyword arguments for each API url endpoint that's implemented.
    def __init__(self):
        # Currently only GET request endpoints are supported
        # TODO: Add endpoints for POST, PUT, DELETE requests and implement them in grapi.py
        self._endpoints = {
            "/api/search/aggregate": ["query", "timerange", "groups"],
            "/api/search/messages": ["query", "timerange"],
            "/api/views/search": [],
            "/api/views/search/<search_id>/execute": []
        }

    def check(self, keys, endpoint):
        # print(endpoint)
        # print(self._endpoints[endpoint])
        if not set(self._endpoints[endpoint]).issubset(set(keys)):
            raise ValueError("Minimum required arguments missing for this API endpoint.\n" +
                             "Given: {0}\n" +
                             "Required: {1}\n".format(keys, self._endpoints))
        else:
            return True