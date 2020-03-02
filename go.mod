module crawler

go 1.13

// Remove the PeerID check because of the difference in identify vs sha2-256 multihash types
replace github.com/libp2p/go-libp2p-secio => ./deps/go-libp2p-secio-patched

// Remove the PeerID verification on the dialer when the ID does not match
replace github.com/libp2p/go-libp2p-swarm => ./deps/go-libp2p-swarm-patched

// Replace the Identity handler with Substrate-compatible
replace github.com/libp2p/go-libp2p => ./deps/go-libp2p-patched

// Development
replace github.com/libp2p/go-libp2p-core => ./deps/go-libp2p-core-patched

require (
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/ipfs/go-cid v0.0.5 // indirect
	github.com/ipfs/go-datastore v0.4.4
	github.com/ipfs/go-ipfs-addr v0.0.1
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/libp2p/go-libp2p v0.5.2
	github.com/libp2p/go-libp2p-core v0.3.1
	github.com/libp2p/go-libp2p-kad-dht v0.5.0
	github.com/libp2p/go-libp2p-kbucket v0.3.1 // indirect
	github.com/libp2p/go-libp2p-peerstore v0.1.4
	github.com/libp2p/go-mplex v0.1.1 // indirect
	github.com/libp2p/go-yamux v1.2.4 // indirect
	github.com/multiformats/go-multiaddr v0.2.1
	github.com/multiformats/go-multiaddr-net v0.1.2 // indirect
	github.com/multiformats/go-multihash v0.0.13
	github.com/multiformats/go-multistream v0.1.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	go.opencensus.io v0.22.3 // indirect
	go.uber.org/multierr v1.5.0 // indirect
	go.uber.org/zap v1.14.0 // indirect
	golang.org/x/crypto v0.0.0-20200221231518-2aa609cf4a9d // indirect
	golang.org/x/lint v0.0.0-20200130185559-910be7a94367 // indirect
	golang.org/x/net v0.0.0-20200301022130-244492dfa37a // indirect
	golang.org/x/sys v0.0.0-20200302150141-5c8b2ff67527 // indirect
	golang.org/x/tools v0.0.0-20200302155637-b1e4e04173e0 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
)
