package sign

import (
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes/config"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes/keygen"
	"golang.org/x/crypto/sha3"
)

func Testkey(t *testing.T, N int, T int) map[party.ID]*config.Config {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "Hermes/keygen-test",
			FinalRoundNumber: keygen.Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        T,
			Group:            curve.Secp256k1{},
		}
		r, err := keygen.Start(info, pl, nil)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}

	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	newConfigs := make(map[party.ID]*config.Config, N)
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r)
		resultRound := r.(*round.Output)
		require.IsType(t, &config.Config{}, resultRound.Result)
		c := resultRound.Result.(*config.Config)
		marshalledConfig, err := cbor.Marshal(c)
		require.NoError(t, err)
		unmarshalledConfig := config.EmptyConfig(curve.Secp256k1{})
		err = cbor.Unmarshal(marshalledConfig, unmarshalledConfig)
		require.NoError(t, err)
		newConfigs[unmarshalledConfig.ID] = unmarshalledConfig
	}
	return newConfigs
}

func TestRound(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()
	N := 4
	T := N - 1

	t.Log("generating configs")
	configs := Testkey(t, N, T)
	partyIDs := test.PartyIDs(N)
	t.Log("done generating configs")

	partyIDs = partyIDs[:T+1]
	publicPoint := configs[partyIDs[0]].PublicPoint()

	messageToSign := []byte("hello")
	messageHash := make([]byte, 64)
	sha3.ShakeSum128(messageHash, messageToSign)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		c := configs[partyID]
		r, err := StartSign(c, partyIDs, messageHash, pl)(nil)
		require.NoError(t, err, "round creation should not result in an error")
		rounds = append(rounds, r)
	}
	//group := configs[partyIDs[0]].Group
	for {
		err, done := test.Rounds(rounds, nil)
		require.NoError(t, err, "failed to process round")
		if done {
			break
		}
	}

	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r, "expected result round")
		resultRound := r.(*round.Output)
		require.IsType(t, &ecdsa.Signature{}, resultRound.Result, "expected taproot signature result")
		signature := resultRound.Result.(*ecdsa.Signature)
		assert.True(t, signature.Verify(publicPoint, messageHash), "expected valid signature")
	}
}
