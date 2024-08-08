package keygen

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/test"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes/config"
)

var group = curve.Secp256k1{}

func checkOutput(t *testing.T, rounds []round.Session) {
	N := len(rounds)
	newConfigs := make([]*config.Config, 0, N)
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r)
		resultRound := r.(*round.Output)
		require.IsType(t, &config.Config{}, resultRound.Result)
		c := resultRound.Result.(*config.Config)
		marshalledConfig, err := cbor.Marshal(c)
		require.NoError(t, err)
		unmarshalledConfig := config.EmptyConfig(group)
		err = cbor.Unmarshal(marshalledConfig, unmarshalledConfig)
		require.NoError(t, err)
		newConfigs = append(newConfigs, unmarshalledConfig)
	}

	firstConfig := newConfigs[0]
	pk := firstConfig.PublicPoint()
	for _, c := range newConfigs {
		assert.True(t, pk.Equal(c.PublicPoint()), "PublicPoint is different")
		//assert.Equal(t, firstConfig.RID, c.RID, "RID is different")
		assert.EqualValues(t, firstConfig.ChainKey, c.ChainKey, "ChainKey is different")
		for id, p := range firstConfig.Public {
			assert.True(t, p.ECDSA.Equal(c.Public[id].ECDSA), "ecdsa not the same", id)
		}
		data, err := c.MarshalBinary()
		assert.NoError(t, err, "failed to marshal new config", c.ID)
		c2 := config.EmptyConfig(group)
		err = c2.UnmarshalBinary(data)
		assert.NoError(t, err, "failed to unmarshal new config", c.ID)
	}
}

func TestKeygen(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 3
	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "Hermes/keygen-test",
			FinalRoundNumber: Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        N - 1,
			Group:            group,
		}
		r, err := Start(info, pl, nil)(nil)
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

	checkOutput(t, rounds)
}

func Testkey(t *testing.T, N int, T int) []*config.Config {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	partyIDs := test.PartyIDs(N)

	rounds := make([]round.Session, 0, N)
	for _, partyID := range partyIDs {
		info := round.Info{
			ProtocolID:       "Hermes/keygen-test",
			FinalRoundNumber: Rounds,
			SelfID:           partyID,
			PartyIDs:         partyIDs,
			Threshold:        T,
			Group:            group,
		}
		r, err := Start(info, pl, nil)(nil)
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

	checkOutput(t, rounds)
	newConfigs := make([]*config.Config, 0, N)
	for _, r := range rounds {
		require.IsType(t, &round.Output{}, r)
		resultRound := r.(*round.Output)
		require.IsType(t, &config.Config{}, resultRound.Result)
		c := resultRound.Result.(*config.Config)
		marshalledConfig, err := cbor.Marshal(c)
		require.NoError(t, err)
		unmarshalledConfig := config.EmptyConfig(group)
		err = cbor.Unmarshal(marshalledConfig, unmarshalledConfig)
		require.NoError(t, err)
		newConfigs = append(newConfigs, unmarshalledConfig)
	}
	return newConfigs
}
func TestRefresh(t *testing.T) {
	pl := pool.NewPool(0)
	defer pl.TearDown()

	N := 4
	T := N - 2
	configs := Testkey(t, N, T)

	rounds := make([]round.Session, 0, N)
	for _, c := range configs {
		info := round.Info{
			ProtocolID:       "Hermes/refresh-test",
			FinalRoundNumber: Rounds,
			SelfID:           c.ID,
			PartyIDs:         c.PartyIDs(),
			Threshold:        N - 2,
			Group:            group,
		}
		r, err := Start(info, pl, c)(nil)
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
	checkOutput(t, rounds)
}
