package Hermes

import (
	"crypto/rand"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"math"
	"sync"
	"testing"
)

func do(t *testing.T, id party.ID, ids []party.ID, threshold int, message []byte, pl *pool.Pool, n *test.Network, wg *sync.WaitGroup, cond *sync.Cond, counter *int) {

	defer wg.Done()
	h, err := protocol.NewMultiHandler(Keygen(curve.Secp256k1{}, id, ids, threshold, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(id, h, n)
	r, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
	c := r.(*Config)

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

	h, err = protocol.NewMultiHandler(Refresh(c, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)
	r, err = h.Result()
	require.NoError(t, err)
	require.IsType(t, &Config{}, r)
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

	h, err = protocol.NewMultiHandler(Sign(c, ids, message, pl), nil)
	require.NoError(t, err)
	test.HandlerLoop(c.ID, h, n)
	signResult, err := h.Result()
	require.NoError(t, err)
	require.IsType(t, &ecdsa.Signature{}, signResult)
	signature := signResult.(*ecdsa.Signature)
	assert.True(t, signature.Verify(c.PublicPoint(), message))
}

func TestHermes(t *testing.T) {

	N := 3
	T := N - 1
	message := []byte("hello")

	partyIDs := test.PartyIDs(N)

	n := test.NewNetwork(partyIDs)

	var wg sync.WaitGroup
	wg.Add(N)

	cond := sync.NewCond(&sync.Mutex{})
	counter := new(int)
	*counter = N
	for _, id := range partyIDs {
		pl := pool.NewPool(1)
		defer pl.TearDown()
		go do(t, id, partyIDs, T, message, pl, n, &wg, cond, counter)
	}
	wg.Wait()
}

func TestStart(t *testing.T) {
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
		t.Run(tt.name, func(t *testing.T) {
			c.Threshold = tt.threshold
			var err error
			_, err = Keygen(group, selfID, tt.partyIDs, tt.threshold, pl)(nil)
			t.Log(err)
			assert.Error(t, err)
		})
	}
}
