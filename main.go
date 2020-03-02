package main

/*
	Polkadot DHT Crawler - (C) 2020 Atredis Partners
	MIT License
*/

// Derived from https://github.com/whyrusleeping/ipfs-counter/blob/master/main.go

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"log"

	ds "github.com/ipfs/go-datastore"
	ipfsaddr "github.com/ipfs/go-ipfs-addr"
	libp2p "github.com/libp2p/go-libp2p"

	host "github.com/libp2p/go-libp2p-core/host"
	"github.com/libp2p/go-libp2p-core/network"
	peer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/libp2p/go-libp2p-core/protocol"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	pstore "github.com/libp2p/go-libp2p-peerstore"
	"github.com/multiformats/go-multiaddr"
	mh "github.com/multiformats/go-multihash"
)

// CrawlerUserAgent is what we advertise to each peer during identify
const CrawlerUserAgent string = "parity-polkadot/v0.7.18-fc100e65-x86_64-linux-gnu (unknown)"

// DefaultBootstrapAddresses is the list of kusama CC3 bootstrap servers
var DefaultBootstrapAddresses = []string{
	"/dns4/p2p.cc3-0.kusama.network/tcp/30100/p2p/QmeCit3Nif4VfNqrEJsdYHZGcKzRCnZvGxg6hha1iNj4mk",
	"/dns4/p2p.cc3-1.kusama.network/tcp/30100/p2p/QmchDJtEGiEWf7Ag58HNoTg9jSGzxkSZ23VgmF6xiLKKsZ",
	"/dns4/p2p.cc3-2.kusama.network/tcp/30100/p2p/QmYG1YUekKETmD68yFKbjXDRbSAFULRRJpb1SbQPuSKA87",
	"/dns4/p2p.cc3-3.kusama.network/tcp/30100/p2p/QmQv5EXUAfVt4gbupiuLDZP2Gd7ykK6YuXoYPkyLfLtJch",
	"/dns4/p2p.cc3-4.kusama.network/tcp/30100/p2p/QmP3zYRhAxxw4fDf6Vq5agM8AZt1m2nKpPAEDmyEHPK5go",
	"/dns4/p2p.cc3-5.kusama.network/tcp/30100/p2p/QmdePe9MiAJT4yHT2tEwmazCsckAZb19uaoSUgRDffPq3G",
	"/dns4/kusama-bootnode-0.paritytech.net/tcp/30333/p2p/QmTFUXWi98EADXdsUxvv7t9fhJG1XniRijahDXxdv1EbAW",
	"/dns4/kusama-bootnode-0.paritytech.net/tcp/30334/ws/p2p/QmTFUXWi98EADXdsUxvv7t9fhJG1XniRijahDXxdv1EbAW",
	"/dns4/kusama-bootnode-1.paritytech.net/tcp/30333/p2p/Qmf58BhdDSkHxGy1gX5YUuHCpdYYGACxQM3nGWa7xJa5an",
}

// Peer tracks an identified P2P peer
type Peer struct {
	Info        pstore.PeerInfo `json:"info"`
	LastUpdated time.Time       `json:"last_updated"`
	Endpoint    string          `json:"endpoint"`
	Version     string          `json:"version"`
	Protocols   []string        `json:"protocols"`
	External    bool            `json:"external"`
}

var endpoints = make(map[string]Peer)
var endpointMutex sync.Mutex

func endpointStore(endpoint string, p Peer) {
	endpointMutex.Lock()
	defer endpointMutex.Unlock()

	p.LastUpdated = time.Now()
	p.Endpoint = endpoint

	if found, ok := endpoints[endpoint]; ok {
		found.LastUpdated = time.Now()
		if p.Version != "" {
			found.Version = p.Version
		}
		if len(p.Protocols) != 0 {
			found.Protocols = p.Protocols
		}
		endpoints[endpoint] = p
		return
	}

	p.External = !isPrivate(p.Info.Addrs[0])
	endpoints[endpoint] = p

	if p.External {
		log.Printf("new external endpoint %s @ %s", p.Info.ID.String(), endpoint)
		startPolling(p)
	}
}

func endpointCount() int {
	endpointMutex.Lock()
	defer endpointMutex.Unlock()
	return len(endpoints)
}

func endpointToPeers() []Peer {
	endpointMutex.Lock()
	defer endpointMutex.Unlock()

	res := []Peer{}
	for ep, p := range endpoints {
		xpeer := p
		xpeer.Endpoint = ep
		res = append(res, xpeer)
	}
	return res
}

func getRandomString() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	o, err := mh.Encode(buf, mh.SHA2_256)
	if err != nil {
		panic(err)
	}
	return string(o)
}

func bootstrapPeers() {

	data, err := ioutil.ReadFile("endpoints.jsonl")
	if err == nil {
		endpointMutex.Lock()
		ext := 0
		for _, line := range strings.Split(string(data), "\n") {
			endpoint := Peer{}

			err = json.Unmarshal([]byte(line), &endpoint)
			if err == nil && endpoint.Info.ID.String() != "" {
				endpoint.External = !isPrivate(endpoint.Info.Addrs[0])
				if endpoint.External {
					ext++
				}
				endpoints[endpoint.Endpoint] = endpoint
			}
		}

		log.Printf("loaded %d (%d external) endpoints from endpoints.jsonl", len(endpoints), ext)
		endpointMutex.Unlock()
	}

	for _, a := range DefaultBootstrapAddresses {
		loadBootstrap(a)
	}
}

func bootstrapArgs() {
	for _, a := range os.Args[1:] {
		// Make it easier to specify these on the command-line
		if !strings.HasPrefix(a, "/") {
			a = "/" + a
		}
		loadBootstrap(a)
	}
}

func loadBootstrap(addr string) {
	ia, err := ipfsaddr.ParseString(addr)
	if err != nil {
		log.Printf("invalid bootstrap peer address %s: %s", addr, err)
		return
	}

	p := Peer{
		Info: pstore.PeerInfo{
			ID:    ia.ID(),
			Addrs: []multiaddr.Multiaddr{ia.Transport()},
		},
	}

	ma := ia.Transport()
	endpointStore(ma.String(), p)
}

func main() {

	// Always use SHA2-256 hashing of the Peer ID
	peer.AdvancedEnableInlining = false

	if len(os.Args) > 1 {
		// Bootstrap from command-line arguments
		bootstrapArgs()
	} else {
		// Bootstrap from file
		bootstrapPeers()
	}

	peers := endpointToPeers()
	for _, t := range peers {
		if t.External {
			startPolling(t)
		}
	}

	for {
		if endpointCount() == 0 {
			time.Sleep(time.Second * 15)
			continue
		}

		fd, _ := os.Create("endpoints.jsonl")
		endpointMutex.Lock()

		log.Printf("saving %d endpoints to disk", len(endpoints))
		for _, endpoint := range endpoints {
			b, _ := json.Marshal(endpoint)
			b = append(b, '\n')
			fd.Write(b)
		}

		endpointMutex.Unlock()
		fd.Close()

		time.Sleep(time.Second * 15)
	}
}

// Connect and repeatedly poll for additional peers
func startPolling(target Peer) {

	go func(t Peer) {

		log.Printf("connecting to peer %s (%s) %s", target.Endpoint, target.Info.ID.String(), target.Version)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		h, err := libp2p.New(
			ctx,
			libp2p.ListenAddrStrings("/ip4/127.0.0.1/tcp/0"),
			libp2p.UserAgent(CrawlerUserAgent),
			libp2p.DisableRelay(),
		)
		if err != nil {
			log.Printf("failed to create libp2p client for %v", t)
			h.Close()
			return
		}

		// Set appropriate advertised protocols for substrate/polkadot
		// ["/substrate/ksmcc3/5","/substrate/ksmcc3/4","/substrate/ksmcc3/3","/ipfs/ping/1.0.0","/ipfs/id/1.0.0","/ipfs/kad/1.0.0"]

		k := NewKusamaHandler(h)
		h.SetStreamHandler(protocol.ID("/substrate/ksmcc3/5"), k.KusamaHandler)
		h.SetStreamHandler(protocol.ID("/substrate/ksmcc3/4"), k.KusamaHandler)
		h.SetStreamHandler(protocol.ID("/substrate/ksmcc3/3"), k.KusamaHandler)

		// Patches to id.go remove push and delta

		mds := ds.NewMapDatastore()
		mdht := dht.NewDHT(ctx, h, mds)

		// log.Printf("connecting to %s via %v", t.Info.ID.String(), t.Info.Addrs)
		if err := h.Connect(ctx, t.Info); err != nil {
			log.Printf("failed to connect to %s: %s", t.Endpoint, err)
			h.Close()
			return
		}

		for {

			if err := scrapePeers(h, t.Info.ID.String(), mdht); err != nil {
				mdht.RefreshRoutingTable()
				continue
			}

			if endpointCount() < 10 {
				time.Sleep(time.Second)
				continue
			}

			if endpointCount() < 100 {
				time.Sleep(time.Second * 5)
				continue
			}

			time.Sleep(time.Second * 15)
			mdht.RefreshRoutingTable()
		}

		// Close and restart
		h.Close()

	}(target)
}

var patIPv4 = regexp.MustCompile(`^/ip4/([\d\.]+)/tcp/(\d+)`)
var patIPv46 = regexp.MustCompile(`^/ip6/::ffff:([\d\.]+)/tcp/(\d+)`)
var patIPv6 = regexp.MustCompile(`^/ip6/([a-fA-F\d\.\:]+)/tcp/(\d+)`)
var patDNS = regexp.MustCompile(`^/dns\d+/`)

func scrapePeers(h host.Host, peerID string, mdht *dht.IpfsDHT) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peers, err := mdht.GetClosestPeers(ctx, getRandomString())
	if err != nil {
		return err
	}

	for p := range peers {

		if p == h.ID() {
			continue
		}

		peerVersion := ""
		if foundVersion, err := h.Peerstore().Get(p, "AgentVersion"); err == nil {
			peerVersion = fmt.Sprint(foundVersion)
		}

		peerProtocols, _ := h.Peerstore().GetProtocols(p)

		info, err := mdht.FindPeer(ctx, p)
		if err != nil {
			log.Printf("failed to find peer %s: %s", p, err)
			continue
		}

		for _, a := range info.Addrs {
			addr := a.String()

			// Convert ip6/::ffff: to ip4/
			addr = strings.Replace(addr, "ip6/::ffff:", "ip4/", 1)
			rma, _ := multiaddr.NewMultiaddr(addr)

			endp := pstore.PeerInfo{
				ID:    info.ID,
				Addrs: []multiaddr.Multiaddr{rma},
			}

			endpointStore(addr, Peer{Info: endp, Version: peerVersion, Protocols: peerProtocols, External: !isPrivate(rma)})
		}
	}

	return nil
}

func isPrivate(a multiaddr.Multiaddr) bool {
	addr := a.String()

	if m := patIPv4.FindStringSubmatch(addr); len(m) == 3 {
		return isPrivateIP(m[1])
	}

	if m := patIPv46.FindStringSubmatch(addr); len(m) == 3 {
		return isPrivateIP(m[1])
	}

	if m := patIPv6.FindStringSubmatch(addr); len(m) == 3 {
		return isPrivateIP(m[1])
	}

	if patDNS.MatchString(addr) {
		return false
	}

	log.Printf("unknown address format for %s", addr)
	return true
}

// isPrivateIP filters non-public IP space (borrowed from critical research)
func isPrivateIP(s string) bool {
	ip := net.ParseIP(s)
	if ip == nil {
		return true
	}

	// IPv4
	ip4 := ip.To4()
	if ip4 != nil {
		if bytes.HasPrefix(ip4, []byte{127}) ||
			bytes.HasPrefix(ip4, []byte{0}) ||
			bytes.HasPrefix(ip4, []byte{169, 254}) ||
			bytes.HasPrefix(ip4, []byte{10}) ||
			bytes.HasPrefix(ip4, []byte{192, 168}) ||
			(ip4[0] == 172 && (ip4[1] >= 16 && ip4[1] <= 31)) ||
			ip4[0] > 223 {
			return true
		}
		return false
	}

	// IPv6
	if bytes.HasPrefix(ip, []byte{0xfc, 0x00}) ||
		bytes.HasPrefix(ip, []byte{0xfe, 0x80}) ||
		bytes.HasPrefix(ip, []byte{0xff, 0x00}) ||
		bytes.HasPrefix(ip, []byte{0x01, 0x80}) ||
		bytes.HasPrefix(ip, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}) ||
		bytes.HasPrefix(ip, []byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff}) {
		return true
	}

	ips := ip.String()
	if ips == "::" || ips == "::1" || ips == "1::1" {
		return true
	}

	return false
}

// KusamaHandler is a minimal implementation of the substrate/kusama protocol
type KusamaHandler struct {
	Host host.Host
}

// NewKusamaHandler returns a handler for this peer
func NewKusamaHandler(h host.Host) *KusamaHandler {
	return &KusamaHandler{Host: h}
}

// KusamaHandler handles the stream
func (p *KusamaHandler) KusamaHandler(s network.Stream) {
	defer s.Close()

	buf := make([]byte, 1024)
	for {
		n, err := io.ReadAtLeast(s, buf, 1)
		if err != nil {
			return
		}

		data := buf[:n]
		log.Printf("incoming data from %s protocol %s : %d bytes", s.Conn().RemoteMultiaddr(), s.Protocol(), len(data))
	}
}
