package sign

import (
	"errors"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/ecdsa"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var _ round.Round = (*round3)(nil)

type round3 struct {
	*round2

	delta map[party.ID]curve.Scalar
	v     map[party.ID]curve.Scalar
	R     curve.Point
}

type broadcast3 struct {
	round.ReliableBroadcastContent
	V     curve.Scalar
	Delta curve.Scalar
}

// StoreBroadcastMessage implements round.BroadcastRound.
//
// - store Γⱼ
func (r *round3) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast3)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	from := msg.From
	r.v[from] = body.V
	r.delta[from] = body.Delta
	return nil
}

func (r *round3) VerifyMessage(msg round.Message) error { return nil }

func (r *round3) StoreMessage(msg round.Message) error { return nil }

func (r *round3) Finalize(out chan<- *round.Message) (round.Session, error) {
	vInv := r.Group().NewScalar()
	delta := r.Group().NewScalar()
	for _, id := range r.PartyIDs() {
		vInv.Add(r.v[id])
		delta.Add(r.delta[id])
	}
	vInv.Invert()
	s := r.Group().NewScalar().Set(delta)
	s.Mul(vInv)
	signature := &ecdsa.Signature{
		R: r.R,
		S: s,
	}

	if !signature.Verify(r.PublicKey, r.Message) {
		return r.AbortRound(errors.New("failed to validate signature")), nil
	}
	r.round1.prg.End()
	return r.ResultRound(signature), nil
}

// RoundNumber implements round.Content.
func (broadcast3) RoundNumber() round.Number { return 3 }

// BroadcastContent implements round.BroadcastRound.
func (r *round3) BroadcastContent() round.BroadcastContent {
	return &broadcast3{
		V:     r.Group().NewScalar(),
		Delta: r.Group().NewScalar(),
	}
}
func (r *round3) MessageContent() round.Content { return nil }

// Number implements round.Round.
func (round3) Number() round.Number { return 3 }
