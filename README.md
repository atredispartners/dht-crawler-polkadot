# DHT Crawler for the Polkadot Network (Kusama CC3)

This is a simple DHT crawler for Polkadot, configured for the Kusama CC3 network.

This crawler will repeatedly connect to Polkadot nodes with external IP addresses, saving the results in a local file named `endpoints.jsonl`.

This crawler may create thousands of TCP connections, ensure that the file descriptor limit is increased prior to running with:

```
$ ulimit -n 99999
```

The crawling process was inspired by https://github.com/whyrusleeping/ipfs-counter/blob/master/main.go

Note that the initial bootstrap process can be slow and takes a long time to find new peers. 

To speed things up, specify a local Polkadot node endpoint (the PeerID can be bogus):

```
$ go run main.go /ip4/10.10.10.3/tcp/30333/p2p/QmeCit3Nif4VfNqrEJsdYHZGcKzRCnZvGxg6hha1iNj4mk
```