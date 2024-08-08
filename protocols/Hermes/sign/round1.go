package sign

import (
	"crypto/rand"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/sample"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

var _ round.Round = (*round1)(nil)

type round1 struct {
	*round.Helper
	prg       PRG
	PublicKey curve.Point

	SecretECDSA curve.Scalar
	ECDSA       map[party.ID]curve.Point

	Message []byte
}

// VerifyMessage implements round.Round.
func (round1) VerifyMessage(round.Message) error { return nil }

// StoreMessage implements round.Round.
func (round1) StoreMessage(round.Message) error { return nil }

// Finalize implements round.Round
//
// - sample kᵢ, γᵢ <- 𝔽,
// - Γᵢ = [γᵢ]⋅G
// - Gᵢ = Encᵢ(γᵢ;νᵢ)
// - Kᵢ = Encᵢ(kᵢ;ρᵢ)
//
// NOTE
// The protocol instructs us to broadcast Kᵢ and Gᵢ, but the protocol we implement
// cannot handle identify aborts since we are in a point to point model.
// We do as described in [LN18].
//
// In the next round, we send a hash of all the {Kⱼ,Gⱼ}ⱼ.
// In two rounds, we compare the hashes received and if they are different then we abort.
func (r *round1) Finalize(out chan<- *round.Message) (round.Session, error) {
	k := sample.Scalar(rand.Reader, r.Group())
	phi := sample.Scalar(rand.Reader, r.Group())
	w := r.Group().NewScalar().Set(r.SecretECDSA)

	flag := false
	for _, id := range r.PartyIDs() {
		if r.SelfID() == id {
			flag = true
			continue
		}
		if flag {
			k.Add(r.prg.Rand(id, r.Group()))
			phi.Add(r.prg.Rand(id, r.Group()))
			w.Add(r.prg.Rand(id, r.Group()))
		} else {
			k.Sub(r.prg.Rand(id, r.Group()))
			phi.Sub(r.prg.Rand(id, r.Group()))
			w.Sub(r.prg.Rand(id, r.Group()))
		}
	}
	gk := k.ActOnBase()

	broadcastMsg := broadcast2{Gk: gk}
	if err := r.BroadcastMessage(out, &broadcastMsg); err != nil {
		return r, err
	}

	//p2p
	n := r.N()
	t := n - 1
	ids := r.PartyIDs()
	index := 0
	for j, id := range ids {
		if id == r.SelfID() {
			index = j
			break
		}
	}
	temp := 0
	//如果t是偶数
	if t%2 == 0 {
		temp = t / 2
	} else {
		if index < (n / 2) {
			temp = n / 2
		} else {
			temp = n/2 - 1
		}
	}

	for i := 1; i <= temp; i++ {
		id := ids[(index+i)%n]
		err := r.SendMessage(out, &message2{
			K:   k,
			Phi: phi,
			W:   w,
		}, id)
		if err != nil {
			return nil, err
		}
	}
	for i := temp + 1; i < n; i++ {
		id := ids[(index+i)%n]
		err := r.SendMessage(out, &message2{
			K:   r.Group().NewScalar(),
			Phi: r.Group().NewScalar(),
			W:   r.Group().NewScalar(),
		}, id)
		if err != nil {
			return nil, err
		}
	}

	return &round2{
		round1: r,
		k:      map[party.ID]curve.Scalar{r.SelfID(): k},
		phi:    map[party.ID]curve.Scalar{r.SelfID(): phi},
		w:      map[party.ID]curve.Scalar{r.SelfID(): w},
		gk:     map[party.ID]curve.Point{r.SelfID(): gk},
	}, nil
}

// MessageContent implements round.Round.
func (round1) MessageContent() round.Content            { return nil }
func (round1) BroadcastContent() round.BroadcastContent { return nil }

// Number implements round.Round.
func (round1) Number() round.Number { return 1 }
