package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/cmp"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type arrayFlags []string

func (i *arrayFlags) String() string {
	return "my string representation"
}

func (i *arrayFlags) Set(value string) error {
	*i = append(*i, value)
	return nil
}

var p2p arrayFlags

const (
	MaxParty int = 2
	Timeout      = 1 * time.Minute
	CMD      int = 1
	PARAM    int = 2
)

//type client chan<- string // an outgoing message channel

func nextId(ids party.IDSlice, id int, max int) (idx int, name party.ID) {
	nid := id + 1
	if nid > max {
		nid = 0
	}
	return nid, ids[nid]
}

func main() {
	var id int
	var srv string
	flag.IntVar(&id, "id", 0, "party id")
	flag.StringVar(&srv, "srv", "", "local server port")
	flag.Var(&p2p, "p2p", "-srv localhost:7000 -srv localhost:8000 -srv localhost:9000")
	flag.Parse()

	threshold := 2
	group := curve.Secp256k1{}

	ids := party.IDSlice{"a", "b", "c"}

	nm := map[party.ID]party.IDSlice{
		"a": {"b", "c"}, "b": {"a", "c"}, "c": {"a", "b"},
	}
	uid := ids[id]
	idm := nm[uid]
	log.Println("Start party:", uid)

	nid, npid := nextId(ids, id, MaxParty)
	_, nnpid := nextId(ids, nid, MaxParty)

	//log.Printf("Nextid:%d Thid:%d", nid, nnid)
	log.Printf("Two party:%s Three party:%s", npid, nnpid)

	network := test.NewNetworkP2P(uid, idm)

	go processCmd(uid, network, ids, threshold, group)

	for _, host := range p2p {
		go func() {
			conn, err := waitForServer(host)
			if err != nil {
				log.Fatal(err)
			}
			//if idx == 0 {
			go mustCopy(conn, os.Stdin)
			//}
			network.HandleConn(conn, npid)
		}()
	}

	if srv != "" {
		listener, err := net.Listen("tcp", srv)
		if err != nil {
			log.Fatal(err)
		}
		for {
			conn, err := listener.Accept()
			if err != nil {
				log.Print(err)
				continue
			}
			//log.Printf("Handle local:%s remote:%s", conn.LocalAddr(), conn.RemoteAddr())
			go network.HandleConn(conn, nnpid)
		}
	} else {
		////
		quit := make(chan os.Signal)
		signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
		<-quit
		log.Print("Shutdown Server ...")

	}
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

func mustCopy(dst net.Conn, src io.Reader) {
	if _, err := io.Copy(dst, src); err != nil {
		log.Println("Conn Error:", err)
	}
}

func processCmd(uid party.ID, tcp *test.NetworkP2P, ids party.IDSlice, threshold int, group curve.Secp256k1) {
	f := fmt.Sprintf("config_%s.txt", uid)
	pl := pool.NewPool(0)
	defer pl.TearDown()

	for cmd := range tcp.CMD() {
		cmdLine := strings.Split(cmd, ":")
		log.Println("Execute cmd:", cmd)
		switch cmdLine[CMD] {
		case "sign":
			if len(cmdLine) < 3 {
				log.Printf("Please input sign message")
				break
			}
			messageToSign := cmdLine[PARAM] //params
			signers := ids[:threshold+1]
			cfg, err := loadConfig(f, group)
			err = CMPSign1(cfg, []byte(messageToSign), signers, tcp, pl)
			if err != nil {
				log.Print("Error", err)
			}
			log.Printf("Sign %s OK", messageToSign)

		case "addr":
			path := cmdLine[PARAM]
			cfgOld, err := loadConfig(f, group)
			if err != nil {
				log.Println("load config error:", err)
			}

			//path := "m/44/60/0/0/1"
			genAddress(cfgOld, path)

		case "refresh":
			cfgOld, err := loadConfig(f, group)
			if err != nil {
				log.Println("load config error:", err)
			}

			cfgNew, err := CMPRefresh1(cfgOld, tcp, pl)
			if err != nil {
				log.Println("load refresh error:", err)
			}

			cfjo, _ := json.Marshal(cfgOld)
			cfjn, _ := json.Marshal(cfgNew)
			log.Printf("refresh old cfg:%s", cfjo)
			log.Printf("refresh new cfg:%s", cfjn)

			pa1, err := cfgOld.PublicPoint().MarshalBinary()
			log.Printf("Old public bip32 compress:%x", pa1)
			pa2, err := cfgNew.PublicPoint().MarshalBinary()
			log.Printf("New public bip32 compress:%x", pa2)

		case "gen":
			cfg, err := CMPKeygen1(uid, ids, threshold, tcp, pl)
			if err != nil {
				log.Println("Error:", err)
			}
			cfj, _ := json.Marshal(cfg)
			log.Printf("cfg:%s", cfj)

			writeConfig(cfg, f)

		}
	}
}
func genAddress(cfgOld *cmp.Config, path string) {
	cfgNew, err := cfgOld.DeriveBIP44(path)
	if err != nil {
		log.Println("DeriveBipError", err)
	}
	log.Printf("BIP44:Path: %s", path)
	pubkey, err := cfgNew.PublicPoint().MarshalBinary()
	log.Printf("pubkey compress:%x", pubkey)
}

func writeConfig(cfg *cmp.Config, f string) {
	cfb, _ := cfg.MarshalBinary()
	ioutil.WriteFile(f, cfb, 0644)
}

func loadConfig(f string, group curve.Secp256k1) (*cmp.Config, error) {
	cfb, err := ioutil.ReadFile(f)
	if err != nil {
		log.Println("Error", err)
	}
	//debug
	//log.Printf("Config Content:%s", cfb)
	cfg := cmp.EmptyConfig(group)
	err = cfg.UnmarshalBinary(cfb)
	if err != nil {
		log.Println("Error", err)
	}
	return cfg, err
}
func CMPKeygen1(id party.ID, ids party.IDSlice, threshold int, n test.INetwork, pl *pool.Pool) (*cmp.Config, error) {
	h, err := protocol.NewMultiHandler(cmp.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPRefresh1(c *cmp.Config, n test.INetwork, pl *pool.Pool) (*cmp.Config, error) {
	hRefresh, err := protocol.NewMultiHandler(cmp.Refresh(c, pl), nil)
	if err != nil {
		return nil, err
	}
	test.HandlerLoop(c.ID, hRefresh, n)

	r, err := hRefresh.Result()
	if err != nil {
		return nil, err
	}

	return r.(*cmp.Config), nil
}

func CMPSign1(c *cmp.Config, m []byte, signers party.IDSlice, n test.INetwork, pl *pool.Pool) error {
	h, err := protocol.NewMultiHandler(cmp.Sign(c, signers, m, pl), nil)
	if err != nil {
		return err
	}
	test.HandlerLoop(c.ID, h, n)

	signResult, err := h.Result()
	if err != nil {
		return err
	}

	signature := signResult.(*ecdsa.Signature)

	//c.PublicPoint 公钥 m 文本 signature签名
	log.Printf("msg:%s", m)
	prvSig, _ := signature.R.MarshalBinary()
	log.Printf("prvSig:%s ", prvSig)
	if !signature.Verify(c.PublicPoint(), m) {
		return errors.New("failed to verify cmp signature")
	}
	return nil
}
