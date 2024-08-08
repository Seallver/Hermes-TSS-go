package mobile

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/gin-gonic/gin"
	"github.com/taurusgroup/multi-party-sig/internal/btc"
	"github.com/taurusgroup/multi-party-sig/internal/eth"
	"log"
	"strings"
	"sync"
)

var (
	id        = 2
	threshold = 2
	path      = "m/44/0/0/0/1"
	f         = fmt.Sprintf("config_%d.txt", id)
	fr        = fmt.Sprintf("config_new_%d.txt", id)

	//tx        = []byte("hello word hello word hello word hello word")
	tx = hexutil.MustDecode("0xce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008")
)

func TestGoAntalphaLib_GenKey(c *gin.Context, cond_ *sync.Cond, p2p []string) {
	m := MPCDotLib{}
	if keyShare, err := m.GenKey(c, cond_, p2p, id, threshold); err == nil {
		writeFile(keyShare, f)
		m.closeParty(p2p)
		log.Printf("success")
	} else {
		//t.Error(err)
	}
}

func TestGoAntalphaLib_PublicKey() {
	keyShare, err := loadFile(f)
	//if err != nil {
	//	t.Error(err)
	//}
	m := MPCDotLib{}
	px, py, err := m.PublicKey(keyShare, path)
	log.Printf("PubX:%x", px)
	log.Printf("PubY:%x", py)
	log.Printf("ETH Addr:%s", eth.Address(px, py))
	log.Printf("BTC Addr:%s", btc.Address(px, py))
	if err != nil {
		//t.Error(err)
	} else {

	}
}
func TestGoAntalphaLib_RefreshKey(c *gin.Context, cond_ *sync.Cond, p2p []string) {
	keyShare, _ := loadFile(f)
	//if err != nil {
	//	t.Error(err)
	//}
	m := MPCDotLib{}
	if ks, err := m.RefreshKey(c, cond_, p2p, id, threshold, keyShare); err == nil {
		writeFile(ks, f)
		m.closeParty(p2p)
		//t.Log("Success")
	} else {
		//t.Error(err)
	}
}

func TestGoAntalphaLib_Sign(c *gin.Context, cond_ *sync.Cond, p2p []string) {
	keyShare, _ := loadFile(f)
	//if err != nil {
	//	t.Error(err)
	//}
	m := MPCDotLib{}
	r, s, v, _ := m.Sign(c, cond_, p2p, id, threshold, keyShare, path, tx)
	//if err != nil {
	//	t.Error(err)
	//}
	log.Printf("Sig R:%x S:%x v:%x", r, s, v)
	ps := strings.Split(path, "/")
	if len(ps) > 2 {
		var sig []byte
		coinType := ps[2]
		switch coinType {
		case "60", "22": //DER Format SigCompact
			sig, _ = eth.Sign(r, s, v)
			//if err != nil {
			//	t.Error(err)
			//}
			pk, _ := eth.SigToPub(tx, sig)
			//if err != nil {
			//	t.Error(err)
			//}
			log.Printf("RecoverPub:%x", pk)
		case "0":
			//for btc add hash type to der end
			//sig = btc.Signature(r, s)
			sig = btc.ByteToDER(r, s)
		default:
		}
		log.Printf("Sig:%x", sig)
	}
	m.closeParty(p2p)
}
