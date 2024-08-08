package main

import (
	"crypto/rand"
	"fmt"
	"github.com/gin-gonic/gin"
	m2p "github.com/taurusgroup/multi-party-sig/Web/ourexm2p"
	mobile "github.com/taurusgroup/multi-party-sig/Web/ourexmobile"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes/config"
	"math"
	"net/http"
	"sync"
)

type Config = config.Config

func doWeb(cgin *gin.Context, id party.ID, ids []party.ID, threshold int, message []byte, pl *pool.Pool, n *test.Network, wg *sync.WaitGroup, cond *sync.Cond, cond_ *sync.Cond, counter *int) {

	defer wg.Done()
	h, _ := protocol.NewMultiHandler(Hermes.Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	test.WebHandlerLoop(cgin, id, h, n, cond_)

	r, _ := h.Result()
	c := r.(*Config)

	cond.L.Lock()
	*counter--
	if *counter == 0 {
		*counter = len(ids) // 重置counter
		cond.Broadcast()    // 唤醒所有等待的线程
	} else {
		cond.Wait() // 进入等待状态
	}
	cond.L.Unlock()

	h, _ = protocol.NewMultiHandler(Hermes.Refresh(c, pl), nil)
	test.WebHandlerLoop(cgin, c.ID, h, n, cond_)
	r, _ = h.Result()
	c = r.(*Config)

	cond.L.Lock()
	*counter--
	if *counter == 0 {
		*counter = len(ids) // 重置counter
		cond.Broadcast()    // 唤醒所有等待的线程
	} else {
		fmt.Println("sleep")
		cond.Wait() // 进入等待状态
		fmt.Println("pass")
	}
	cond.L.Unlock()
	//time.Sleep(1 * time.Millisecond)

	h, _ = protocol.NewMultiHandler(Hermes.Sign(c, ids, message, pl), nil)
	test.WebHandlerLoop(cgin, c.ID, h, n, cond_)
}

func doErrorTest(r *gin.Engine) {
	group := curve.Secp256k1{}
	N := 6
	T := 3
	pl := pool.NewPool(0)
	defer pl.TearDown()
	configs, partyIDs := test.GenerateConfig(group, N, T, rand.Reader, pl)

	//m := []byte("HELLO")
	selfID := partyIDs[0]
	c := configs[selfID]
	tests := []struct {
		name      string
		partyIDs  []party.ID
		threshold int
	}{
		{
			"N threshold",
			partyIDs,
			N,
		},
		{
			"T threshold",
			partyIDs[:T],
			N,
		},
		{
			"-1 threshold",
			partyIDs,
			-1,
		},
		{
			"max threshold",
			partyIDs,
			math.MaxUint32,
		},
		{
			"max threshold -1",
			partyIDs,
			math.MaxUint32 - 1,
		},
		{
			"no self",
			partyIDs[1:],
			T,
		},
		{
			"duplicate self",
			append(partyIDs, selfID),
			T,
		},
		{
			"duplicate other",
			append(partyIDs, partyIDs[1]),
			T,
		},
	}

	for _, tt := range tests {
		name := tt.name
		threshold := tt.threshold
		partyids := tt.partyIDs
		r.GET("/"+name, func(cgin *gin.Context) {
			c.Threshold = threshold
			var err error
			_, err = Hermes.Keygen(group, selfID, partyids, threshold, pl)(nil)
			cgin.String(http.StatusOK, fmt.Sprintf("Error generating key: %v", err))
		})
	}
}

func doHermesTotalTest(c *gin.Context) {
	N := 3
	T := N - 1
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)

	cond := sync.NewCond(&sync.Mutex{})
	cond_ := sync.NewCond(&sync.Mutex{})
	counter := new(int)
	*counter = N
	for _, id := range partyIDs {
		pl := pool.NewPool(1)
		defer pl.TearDown()
		go doWeb(c, id, partyIDs, T, message, pl, n, &wg, cond, cond_, counter)
	}
	wg.Wait()
}

func start_a(c *gin.Context) {
	m2p.M2p_part(0, "127.0.0.1:7001", nil)
}

func start_server_a(c *gin.Context) {
	srv := c.PostForm("a_srv")
	m2p.M2p_part(0, srv, nil)
}

func start_b(c *gin.Context) {
	p2p := []string{"127.0.0.1:7001"}
	m2p.M2p_part(1, "127.0.0.1:8001", p2p)
}

func start_server_b(c *gin.Context) {
	srv := c.PostForm("b_srv")
	p2p := c.PostFormArray("a_srv")
	m2p.M2p_part(1, srv, p2p)
}

func start_mobile(c *gin.Context) {
	p2p := []string{"127.0.0.1:7001", "127.0.0.1:8001"}
	cond_ := sync.NewCond(&sync.Mutex{})
	mobile.TestGoAntalphaLib_GenKey(c, cond_, p2p)
	mobile.TestGoAntalphaLib_PublicKey()
	mobile.TestGoAntalphaLib_RefreshKey(c, cond_, p2p)
	mobile.TestGoAntalphaLib_Sign(c, cond_, p2p)
}

func start_client_mobile(c *gin.Context) {
	p2p := c.PostFormArray("m_p2p")
	cond_ := sync.NewCond(&sync.Mutex{})
	mobile.TestGoAntalphaLib_GenKey(c, cond_, p2p)
	mobile.TestGoAntalphaLib_PublicKey()
	mobile.TestGoAntalphaLib_RefreshKey(c, cond_, p2p)
	mobile.TestGoAntalphaLib_Sign(c, cond_, p2p)
}

func start_m2p(r *gin.Engine) {
	r.GET("/start_part_a", start_a)
	r.GET("/start_part_b", start_b)
	r.GET("/start_mobile", start_mobile)
}

func start_sc(r *gin.Engine) {
	r.POST("/start_server_a", start_server_a)
	r.POST("/start_server_b", start_server_b)
	r.POST("/start_client_mobile", start_client_mobile)
}
