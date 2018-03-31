# tattle

Tattle examines Rapid7's non-HTTPS TLS certificate scans for novel certificates to log to CT.

It is described at this blog post: http://blog.tim-smith.us/2018/03/moressl-spelunking/ 

It may be invoked as `python -m tattle.main` from the checkout root.

The certificate database, with indices, is about 20 GB. Expect to use up to 100 GB of scratch space for the SQLite write-ahead log.
