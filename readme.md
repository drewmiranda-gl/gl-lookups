# Graylog Lookups

## About

### What is this?

This is a proof of concept (POC) tool to be used with Graylog's lookup table/data adapter feature.

Graylog allows the ability to query an HTTP source for lookups using a specific key, and allowing the returned value to enrich log messages, at time of ingest.

A great example of why you would want to perform a lookup is resolving an IP address to its DNS record (reverse DNS/PTR).

### Why does this exist? What problem is it solving?

While many of the "out of box" data adapters work very well, there are some limitations and in some cases, unexpected behaviors.

These can be separated into two different types of limitations/issues:

* performance
* null values being cached leading to the lookup table/data adapter returning no value, defeating the purpose of using the lookup table in the first place

#### Performance

Using lookup tables in processing pipelines creates a blocking operating where the message can't be writted out to disk (e.g. opensearch) until ALL of the pipelines and pipeline stages finish evaluating and executing. Something like a DNS lookup can create contention that limits the throughput of message processing to how quickly the lookup table can process each request. For DNS requests specifically, there is a mix of valid (DNS server has a result) and invalid (dns server has NO result), and invalid results may take as long to process as the data adapter timeout is set. DNS for example, if the timeout is set to 3s, you're creating a limit on message throughput.

A potential solution to this is to multithread requests via a load balancer so that lookups can be processed in parallel.

#### Empty Values

In the event the data adapter returns a null or "empty" value (which may happen if there is a transient issue with the query/request), the cache for that lookup table will cache that empty value. Be default the cache only expires entries after an amount of time has elapsed since it was last read/queried. This creates a condition that makes lookup tables unreliable and to behave unexpectedly.

A potential solution to this is to cache values and in the event the data adapter returns null/no value, use the last known good value.

### What does this do?

This provides a framework to provide lookup results to graylog, via HTTP requests. For example, DNS or reverse DNS lookups. Implementing outside of graylog allows greater flexibility and error control. In theory, multiple instances of this script can be executed and load balanced behind HA Proxy to increase request throughput, thus increasing message processing throughput in graylog and processing pipeline rules.

## Usage

### Execution

Python script executed as a normal python script would:

```
python3 web.py
```

Script always binds to localhost and cannot be accessed remotely. This is for security reasons.

Argument | Description
---- | ----
`--port` | [TCP] Port to listen on. Default: 8080.

### Web Request

Syntax for querying

```
/?lookup=<lookupType>&key=<keyToLookup>
```

Returns json such as:

```json
{"value": "pfsense.home.arpa"}
```

Argument | Description
---- | ----
`lookup` | type of lookup to perform
`key` | key to lookup

### Lookups

Lookup Type | Description
---- | ----
`rdns` | Reverse DNS (PTR Record). Resolves an IPv4 address to a DNS name. Uses DNS of operating system where script is executing.
`dns` | Resolves a DNS name to its IP address. Uses DNS of operating system where script is executing.