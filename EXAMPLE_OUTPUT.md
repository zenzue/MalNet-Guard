Example run:
```
$ python malnet_guard.py --top 20 --exfil-check --orphan-check --json-out report.json
=== MalNet Guard Report ===
time: 2025-09-06T00:00:00+0000  version: 0.3.0
----------------------------------------------------------------------------------------------------
risk proto laddr                  raddr                  pid   proc               status     reasons
----------------------------------------------------------------------------------------------------
  85 tcp  192.168.1.10:53574      45.155.205.233:6667     922  evilbin            ESTAB      suspicious_port:6667,abuseipdb_score:85
  35 tcp  0.0.0.0:2323            :0                       77  dropbear           LISTEN     suspicious_port:2323
  10 tcp  127.0.0.1:5432          127.0.0.1:56102        1201  postgres           ESTAB      tcp_state:ESTAB,private_remote_ip
----------------------------------------------------------------------------------------------------
[Exfil Window] 10s  sent:1.2 GB  recv:73 MB

[Hidden/Orphan listeners] inodes without owning process: 3 (first 10 shown)
[12345, 45678, 77777]
```
