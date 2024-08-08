package sign

import (
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	k   map[party.ID]curve.Scalar
	phi map[party.ID]curve.Scalar
	w   map[party.ID]curve.Scalar
	gk  map[party.ID]curve.Point
}

type broadcast2 struct {
	round.ReliableBroadcastContent

	Gk curve.Point
}

type message2 struct {
	K   curve.Scalar
	W   curve.Scalar
	Phi curve.Scalar
}

// StoreBroadcastMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	r.gk[msg.From] = body.Gk
	return nil
}

// VerifyMessage implements round.Round.
//
// - verify zkenc(Kⱼ).
func (round2) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
//
// - store Kⱼ, Gⱼ.
func (r *round2) StoreMessage(msg round.Message) error {
	from := msg.From
	body, ok := msg.Content.(*message2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}
	r.k[from] = body.K
	r.w[from] = body.W
	r.phi[from] = body.Phi
	return nil
}

// Finalize implements round.Round
//
// - compute Hash(ssid, K₁, G₁, …, Kₙ, Gₙ).
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	group := r.Group()
	R := group.NewPoint()
	for _, point := range r.gk {
		R = R.Add(point)
	}
	otherids := r.OtherPartyIDs()
	u := group.NewScalar().Set(r.w[r.SelfID()])
	u.Mul(r.phi[r.SelfID()])
	v := group.NewScalar().Set(r.k[r.SelfID()])
	v.Mul(r.phi[r.SelfID()])
	for _, id := range otherids {
		wphi := group.NewScalar().Set(r.w[r.SelfID()])
		wphi.Mul(r.phi[id])
		phiw := group.NewScalar().Set(r.phi[r.SelfID()])
		phiw.Mul(r.w[id])
		u.Add(wphi)
		u.Add(phiw)

		kphi := group.NewScalar().Set(r.k[r.SelfID()])
		kphi.Mul(r.phi[id])
		phik := group.NewScalar().Set(r.phi[r.SelfID()])
		phik.Mul(r.k[id])
		v.Add(kphi)
		v.Add(phik)
	}
	delta := curve.FromHash(r.Group(), r.Message)
	temp := group.NewScalar().Set(R.XScalar())
	temp.Mul(u)
	delta.Mul(r.phi[r.SelfID()])
	delta.Add(temp)

	if err := r.BroadcastMessage(out, &broadcast3{
		V:     v,
		Delta: delta,
	}); err != nil {
		return r, err
	}

	return &round3{
		round2: r,
		v:      map[party.ID]curve.Scalar{r.SelfID(): v},
		delta:  map[party.ID]curve.Scalar{r.SelfID(): delta},
		R:      R,
	}, nil
}

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// MessageContent implements round.Round.
func (r *round2) MessageContent() round.Content {
	return &message2{
		K:   r.Group().NewScalar(),
		Phi: r.Group().NewScalar(),
		W:   r.Group().NewScalar(),
	}
}

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		Gk: r.Group().NewPoint(),
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
