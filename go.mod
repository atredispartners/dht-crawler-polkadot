module crawler

go 1.13

// Remove the PeerID check because of the difference in identify vs sha2-256 multihash types
replace github.com/libp2p/go-libp2p-secio => ./deps/go-libp2p-secio-patched

// Remove the PeerID verification on the dialer when the ID does not match
replace github.com/libp2p/go-libp2p-swarm => ./deps/go-libp2p-swarm-patched

// Replace the Identity handler with Substrate-compatible
replace github.com/libp2p/go-libp2p => ./deps/go-libp2p-patched

// Replace the kbucket upstream with a version pinned to v0.2.3
replace github.com/libp2p/go-libp2p-kbucket => ./deps/go-libp2p-kbucket

require (
	github.com/ipfs/go-datastore v0.4.4
	github.com/ipfs/go-ipfs-addr v0.0.1
	github.com/libp2p/go-libp2p v0.5.0
	github.com/libp2p/go-libp2p-core v0.3.1
	github.com/libp2p/go-libp2p-kad-dht v0.5.0
	github.com/libp2p/go-libp2p-peerstore v0.1.4
	github.com/multiformats/go-multiaddr v0.2.1
	github.com/multiformats/go-multihash v0.0.13
)
