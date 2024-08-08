package sign

import (
	"crypto/sha256"
	"errors"
	"fmt"
	systemhash "hash"

	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/pkg/pool"
	"github.com/taurusgroup/multi-party-sig/pkg/protocol"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes/config"
)

// protocolSignID for the "3 round" variant using echo broadcast.
const (
	protocolSignID                  = "Hermes/sign"
	protocolSignRounds round.Number = 3
)

type PRG struct {
	Seed  map[party.ID]types.RID
	hash  map[party.ID]systemhash.Hash
	nonce map[party.ID]types.RID
}

func StartSign(config *config.Config, signers []party.ID, message []byte, pl *pool.Pool) protocol.StartFunc {
	return func(sessionID []byte) (round.Session, error) {
		group := config.Group
		if config.Threshold < 2 {
			return nil, fmt.Errorf("session: threshold %d is invalid for number of parties %d", config.Threshold, len(config.Public))
		}

		// this could be used to indicate a pre-signature later on
		if len(message) == 0 {
			return nil, errors.New("sign.Create: message is nil")
		}

		info := round.Info{
			ProtocolID:       protocolSignID,
			FinalRoundNumber: protocolSignRounds,
			SelfID:           config.ID,
			PartyIDs:         signers,
			Threshold:        config.Threshold,
			Group:            config.Group,
		}

		helper, err := round.NewSession(info, sessionID, pl, config, types.SigningMessage(message))
		if err != nil {
			return nil, fmt.Errorf("sign.Create: %w", err)
		}

		if !config.CanSign(helper.PartyIDs()) {
			return nil, errors.New("sign.Create: signers is not a valid signing subset")
		}

		// Scale public data
		T := helper.N()
		ECDSA := make(map[party.ID]curve.Point, T)
		PublicKey := group.NewPoint()
		lagrange := polynomial.Lagrange(group, signers)
		// Scale own secret
		SecretECDSA := group.NewScalar().Set(lagrange[config.ID]).Mul(config.ECDSA)
		for _, j := range helper.PartyIDs() {
			public := config.Public[j]
			// scale public key share
			ECDSA[j] = lagrange[j].Act(public.ECDSA)
			PublicKey = PublicKey.Add(ECDSA[j])
		}
		h := make(map[party.ID]systemhash.Hash, T)
		nonce := make(map[party.ID]types.RID, T)
		for _, j := range helper.OtherPartyIDs() {
			nonce[j] = config.RID[j].Copy()
			h[j] = sha256.New()
		}
		return &round1{
			Helper:      helper,
			PublicKey:   PublicKey,
			SecretECDSA: SecretECDSA,
			ECDSA:       ECDSA,
			Message:     message,
			prg: PRG{
				Seed:  config.RID,
				hash:  h,
				nonce: nonce,
			},
		}, nil
	}
}

func (prg *PRG) Rand(id party.ID, group curve.Curve) curve.Scalar {
	prg.hash[id].Write(prg.nonce[id])
	prg.nonce[id] = prg.hash[id].Sum(nil)
	return curve.FromHash(group, prg.nonce[id])
}
func (prg *PRG) End() {
	for id, rid := range prg.nonce {
		prg.Seed[id] = rid.Copy()
	}
}
