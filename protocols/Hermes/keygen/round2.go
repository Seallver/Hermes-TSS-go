package keygen

import (
	"errors"
	"fmt"
	"github.com/taurusgroup/multi-party-sig/internal/round"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/math/polynomial"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
	"github.com/taurusgroup/multi-party-sig/protocols/Hermes/config"
)

var _ round.Round = (*round2)(nil)

type round2 struct {
	*round1

	// VSSPolynomials[j] = Fⱼ(X) = fⱼ(X)•G
	VSSPolynomials map[party.ID]*polynomial.Exponent

	// RIDs[j] = ridⱼ
	Seeds map[party.ID]types.RID
	// ChainKeys[j] = cⱼ
	ChainKeys map[party.ID]types.RID
	// ShareReceived[j] = xʲᵢ
	// share received from party j
	ShareReceived map[party.ID]curve.Scalar
}

type broadcast2 struct {
	round.ReliableBroadcastContent

	// VSSPolynomial = Fᵢ(X) VSSPolynomial
	VSSPolynomial *polynomial.Exponent
	C             types.RID
}
type message2 struct {
	Share curve.Scalar
	RID   types.RID
}

// StoreBroadcastMessage implements round.BroadcastRound.
// - save commitment Vⱼ.
func (r *round2) StoreBroadcastMessage(msg round.Message) error {
	body, ok := msg.Content.(*broadcast2)
	if !ok || body == nil {
		return round.ErrInvalidContent
	}

	// check nil
	if body.VSSPolynomial == nil {
		return round.ErrNilFields
	}

	if err := body.C.Validate(); err != nil {
		return fmt.Errorf("chainkey: %w", err)
	}

	// Save all X, VSSCommitments
	VSSPolynomial := body.VSSPolynomial
	// check that the constant coefficient is 0
	// if refresh then the polynomial is constant
	if !(r.VSSSecret.Constant().IsZero() == VSSPolynomial.IsConstant) {
		return errors.New("vss polynomial has incorrect constant")
	}
	// check deg(Fⱼ) = t
	if VSSPolynomial.Degree() != r.Threshold() {
		return errors.New("vss polynomial has incorrect degree")
	}

	r.VSSPolynomials[msg.From] = body.VSSPolynomial
	r.ChainKeys[msg.From] = body.C
	return nil
}

// VerifyMessage implements round.Round.
func (r *round2) VerifyMessage(msg round.Message) error {
	body := msg.Content.(*message2)
	// check RID length
	if err := body.RID.Validate(); err != nil {
		return fmt.Errorf("rid: %w", err)
	}
	return nil
}

// StoreMessage implements round.Round.
func (r *round2) StoreMessage(msg round.Message) error {
	from, body := msg.From, msg.Content.(*message2)
	Share := body.Share

	r.ShareReceived[from] = Share
	r.Seeds[from].XOR(body.RID)
	return nil
}

// Finalize implements round.Round
//
// - send all committed data.
func (r *round2) Finalize(out chan<- *round.Message) (round.Session, error) {
	for i, v := range r.VSSPolynomials {
		// verify share with VSS
		ExpectedPublicShare := v.Evaluate(r.SelfID().Scalar(r.Group())) // Fⱼ(i)
		PublicShare := r.ShareReceived[i].ActOnBase()
		// X == Fⱼ(i)
		if !PublicShare.Equal(ExpectedPublicShare) {
			return r, errors.New("failed to validate VSS share")
		}
	}
	// c = ⊕ⱼ cⱼ
	chainKey := r.PreviousChainKey
	if chainKey == nil {
		chainKey = types.EmptyRID()
		for _, j := range r.PartyIDs() {
			chainKey.XOR(r.ChainKeys[j])
		}
	}

	// add all shares to our secret
	UpdatedSecretECDSA := r.Group().NewScalar()
	if r.PreviousSecretECDSA != nil {
		UpdatedSecretECDSA.Set(r.PreviousSecretECDSA)
	}
	for _, j := range r.PartyIDs() {
		UpdatedSecretECDSA.Add(r.ShareReceived[j])
	}

	// [F₁(X), …, Fₙ(X)]
	ShamirPublicPolynomials := make([]*polynomial.Exponent, 0, len(r.VSSPolynomials))
	for _, VSSPolynomial := range r.VSSPolynomials {
		ShamirPublicPolynomials = append(ShamirPublicPolynomials, VSSPolynomial)
	}

	// ShamirPublicPolynomial = F(X) = ∑Fⱼ(X)
	ShamirPublicPolynomial, err := polynomial.Sum(ShamirPublicPolynomials)
	if err != nil {
		return r, err
	}

	// compute the new public key share Xⱼ = F(j) (+X'ⱼ if doing a refresh)
	PublicData := make(map[party.ID]*config.Public, len(r.PartyIDs()))
	for _, j := range r.PartyIDs() {
		PublicECDSAShare := ShamirPublicPolynomial.Evaluate(j.Scalar(r.Group()))
		if r.PreviousPublicSharesECDSA != nil {
			PublicECDSAShare = PublicECDSAShare.Add(r.PreviousPublicSharesECDSA[j])
		}
		PublicData[j] = &config.Public{
			ECDSA: PublicECDSAShare,
		}
	}

	UpdatedConfig := &config.Config{
		Group:     r.Group(),
		ID:        r.SelfID(),
		Threshold: r.Threshold(),
		ECDSA:     UpdatedSecretECDSA,
		RID:       r.Seeds,
		ChainKey:  chainKey,
		Public:    PublicData,
	}

	return r.ResultRound(UpdatedConfig), nil
}

// PreviousRound implements round.Round.
func (r *round2) PreviousRound() round.Round { return r.round1 }

// MessageContent implements round.Round.
func (r *round2) MessageContent() round.Content {
	return &message2{
		Share: r.Group().NewScalar(),
	}
}

// RoundNumber implements round.Content.
func (broadcast2) RoundNumber() round.Number { return 2 }

// RoundNumber implements round.Content.
func (message2) RoundNumber() round.Number { return 2 }

// BroadcastContent implements round.BroadcastRound.
func (r *round2) BroadcastContent() round.BroadcastContent {
	return &broadcast2{
		VSSPolynomial: polynomial.EmptyExponent(r.Group()),
	}
}

// Number implements round.Round.
func (round2) Number() round.Number { return 2 }
