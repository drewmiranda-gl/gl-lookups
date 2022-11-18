As of now, this python script only outputs errors and exceptions to journald.

In order to collect these for graylog we need to do the following:

1. use Filebeat and the journald input to read contents of journald and output to json files
    * this will be done with a local instance of filebeat, NOT using graylog-sidecar
2. use a different instance of filebeat to tail the json files wrirtten above

systemctl
 |
 - python3
    |
    - gl_lookup
    - gl_lookup2

```
errors/exceptions -> journald -> filebeat (journald input) -> json file -> filebeat (via graylog-sidecar) -> graylog
```