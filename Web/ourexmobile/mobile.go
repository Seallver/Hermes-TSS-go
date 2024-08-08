package mobile

import (
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes"
	"io/ioutil"
	"log"
	"net"
	"runtime"
	"sync"
	"time"
)

type (
	MPCDotLib struct{}
)

var conns = make(map[string]net.Conn)

const (
	Timeout = 1 * time.Minute
)

func main() {
}
func (p *MPCDotLib) PublicKey(keyShare []byte, path string) ([]byte, []byte, error) {
	group := curve.Secp256k1{}
	cfg, err := loadConfig(keyShare, group)
	if err != nil {
		return nil, nil, err
	}
	bipCfg, err := cfg.DeriveBIP44(path)
	if err != nil {
		return nil, nil, err
	}
	pubKey := bipCfg.PublicPoint()
	return pubKey.XBytes(), pubKey.YBytes(), nil
}

func (p *MPCDotLib) Sign(c *gin.Context, cond_ *sync.Cond, p2p []string, id, threshold int, keyShare []byte, path string, messageToSign []byte) ([]byte, []byte, byte, error) {
	pl := pool.NewPool(runtime.NumCPU())
	defer pl.TearDown()

	ids, _, network := p.initParty(p2p, id)
	signers := ids[:threshold+1]

	time.Sleep(1 * time.Millisecond)
	network.CmdBroadcast <- fmt.Sprintf("bcmd:sign:%s:%s", path, messageToSign)

	group := curve.Secp256k1{}
	cfg, err := loadConfig(keyShare, group)
	bipCfg, err := cfg.DeriveBIP44(path)
	if err != nil {
		return nil, nil, 0, err
	}
	sig, err := HermesSign1(c, bipCfg, messageToSign, signers, network, pl, cond_)
	if err != nil {
		return nil, nil, 0, err
	}

	rb := sig.R.XBytes()
	sb, err := sig.S.MarshalBinary()
	if err != nil {
		return nil, nil, 0, err
	}
	v := sig.RecoverCode()
	log.Printf("PubKey X:%x Y:%x", bipCfg.PublicPoint().XBytes(), bipCfg.PublicPoint().YBytes())
	return rb, sb, v, nil

}

func (p *MPCDotLib) RefreshKey(c *gin.Context, cond_ *sync.Cond, p2p []string, id, threshold int, keyShare []byte) ([]byte, error) {
	pl := pool.NewPool(runtime.NumCPU())
	defer pl.TearDown()

	_, _, network := p.initParty(p2p, id)

	time.Sleep(1 * time.Millisecond)
	network.CmdBroadcast <- "bcmd:refresh"
	group := curve.Secp256k1{}
	cfgOld, err := loadConfig(keyShare, group)
	cfgNew, err := HermesRefresh1(c, cfgOld, network, pl, cond_)
	if err != nil {
		log.Println("load refresh error:", err)
	}
	return cfgNew.MarshalBinary()
}

func (p *MPCDotLib) GenKey(c *gin.Context, cond_ *sync.Cond, p2p []string, id, threshold int) ([]byte, error) {
	pl := pool.NewPool(runtime.NumCPU())
	defer pl.TearDown()

	ids, uid, network := p.initParty(p2p, id)

	time.Sleep(1 * time.Millisecond)
	network.CmdBroadcast <- "bcmd:gen"
	cfg, err := HermesKeygen1(c, uid, ids, threshold, network, pl, cond_)
	if err != nil {
		return nil, err
	}
	shareKey, err := cfg.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return shareKey, nil
}

func (p *MPCDotLib) initParty(p2p []string, id int) (party.IDSlice, party.ID, *test.NetworkP2P) {
	ids := party.IDSlice{"a", "b", "c"}
	nm := map[party.ID]party.IDSlice{
		"a": {"b", "c"}, "b": {"a", "c"}, "c": {"a", "b", "m"},
	}
	uid := ids[id]
	idm := nm[uid]
	log.Println("Start party:", uid)

	network := test.NewNetworkP2P(uid, idm)

	for i, host := range p2p {
		log.Printf("Connected: %d %s", i, host)
		conn, err := waitForServer(host)
		if err != nil {
			log.Fatal(err)
		}
		go network.HandleConn(conn, "")
		conns[host] = conn
	}
	return ids, uid, network
}

func (p *MPCDotLib) closeParty(p2p []string) {
	for i, host := range p2p {
		log.Printf("disconnected: %d %s", i, host)
		conn, _ := conns[host]
		err := conn.Close()
		if err != nil {
			return
		}
	}
}

func HermesKeygen1(c *gin.Context, id party.ID, ids party.IDSlice, threshold int, n test.INetwork, pl *pool.Pool, cond_ *sync.Cond) (*Hermes.Config, error) {
	h, err := protocol.NewMultiHandler(Hermes.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}
	test.WebHandlerLoop(c, id, h, n, cond_)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*Hermes.Config), nil
}
func HermesRefresh1(c_ *gin.Context, c *Hermes.Config, n test.INetwork, pl *pool.Pool, cond_ *sync.Cond) (*Hermes.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(Hermes.Refresh(c, pl), nil)
	if err != nil {
		return nil, err
	}
	test.WebHandlerLoop(c_, c.ID, hRefresh, n, cond_)

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*Hermes.Config), nil
}

func HermesSign1(c_ *gin.Context, c *Hermes.Config, m []byte, signers party.IDSlice, n test.INetwork, pl *pool.Pool, cond_ *sync.Cond) (*ecdsa.Signature, error) {
	h, err := protocol.NewMultiHandler(Hermes.Sign(c, signers, m, pl), nil)
	if err != nil {
		return nil, err
	}
	test.WebHandlerLoop(c_, c.ID, h, n, cond_)

	signResult, err := h.Result()
	if err != nil {
		return nil, err
	}

	signature := signResult.(*ecdsa.Signature)

	if !signature.Verify(c.PublicPoint(), m) {
		return nil, errors.New("failed to verify Hermes signature")
	}

	return signature, nil
}

func waitForServer(host string) (net.Conn, error) {
	deadline := time.Now().Add(Timeout)
	for tries := 0; time.Now().Before(deadline); tries++ {
		conn, err := net.Dial("tcp", host)
		if err == nil {
			return conn, nil // success
		}
		log.Printf("Server not responding (%s); Retrying(%d)...", err, tries)
		time.Sleep(time.Second << uint(tries)) // exponential back-off
	}
	return nil, fmt.Errorf("Server %s failed to respond after %s", host, Timeout)
}
func loadConfig(cfb []byte, group curve.Secp256k1) (*Hermes.Config, error) {
	cfg := Hermes.EmptyConfig(group)
	err := cfg.UnmarshalBinary(cfb)
	if err != nil {
		log.Println("Error", err)
	}
	return cfg, err
}
func writeFile(cfg []byte, f string) {
	if err := ioutil.WriteFile(f, cfg, 0644); err != nil {
		log.Println("Error", err)
	}
}

func loadFile(f string) ([]byte, error) {
	cfb, err := ioutil.ReadFile(f)
	if err != nil {
		log.Println("Error", err)
	}
	return cfb, err
}

//func reverse[S ~[]E, E any](s S) {
//	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
//		s[i], s[j] = s[j], s[i]
//	}
//}
