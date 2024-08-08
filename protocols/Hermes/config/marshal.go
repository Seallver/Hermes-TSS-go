package config

import (
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/taurusgroup/multi-party-sig/internal/types"
	"github.com/taurusgroup/multi-party-sig/pkg/math/curve"
	"github.com/taurusgroup/multi-party-sig/pkg/party"
)

// EmptyConfig creates an empty Config with a fixed group, ready for unmarshalling.
//
// This needs to be used for unmarshalling, otherwise the points on the curve can't
// be decoded.
func EmptyConfig(group curve.Curve) *Config {
	return &Config{
		Group: group,
	}
}

type configMarshal struct {
	ID        party.ID
	Threshold int
	ECDSA     curve.Scalar
	RID       []cbor.RawMessage
	ChainKey  types.RID
	Public    []cbor.RawMessage
}
type publicMarshal struct {
	ID    party.ID
	ECDSA curve.Point
}
type ridMarshal struct {
	ID  party.ID
	RID types.RID
}

func (c *Config) MarshalBinary() ([]byte, error) {
	ps := make([]cbor.RawMessage, 0, len(c.Public))
	for _, id := range c.PartyIDs() {
		p := c.Public[id]
		pm := &publicMarshal{
			ID:    id,
			ECDSA: p.ECDSA,
		}
		data, err := cbor.Marshal(pm)
		if err != nil {
			return nil, err
		}
		ps = append(ps, data)
	}
	pr := make([]cbor.RawMessage, 0, len(c.RID))
	for _, id := range c.PartyIDs() {
		r := c.RID[id]
		pm := &ridMarshal{
			ID:  id,
			RID: r,
		}
		data, err := cbor.Marshal(pm)
		if err != nil {
			return nil, err
		}
		pr = append(pr, data)
	}
	return cbor.Marshal(&configMarshal{
		ID:        c.ID,
		Threshold: c.Threshold,
		ECDSA:     c.ECDSA,
		RID:       pr,
		ChainKey:  c.ChainKey,
		Public:    ps,
	})
}

func (c *Config) UnmarshalBinary(data []byte) error {
	if c.Group == nil {
		return errors.New("config must be initialized using EmptyConfig")
	}
	cm := &configMarshal{
		ECDSA: c.Group.NewScalar(),
	}
	if err := cbor.Unmarshal(data, &cm); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// check ECDSA
	if cm.ECDSA.IsZero() {
		return errors.New("config: ECDSA  secret key is zero")
	}

	// handle public parameters
	ps := make(map[party.ID]*Public, len(cm.Public))
	for _, pm := range cm.Public {
		p := &publicMarshal{
			ECDSA: c.Group.NewPoint(),
		}
		if err := cbor.Unmarshal(pm, p); err != nil {
			return fmt.Errorf("config: party %s: %w", p.ID, err)
		}
		if _, ok := ps[p.ID]; ok {
			return fmt.Errorf("config: party %s: duplicate entry", p.ID)
		}

		// handle our own key separately
		if p.ID == cm.ID {
			ps[p.ID] = &Public{
				ECDSA: cm.ECDSA.ActOnBase(),
			}
			continue
		}

		if p.ECDSA.IsIdentity() {
			return fmt.Errorf("config: party %s: ECDSA is identity", p.ID)
		}
		ps[p.ID] = &Public{
			ECDSA: p.ECDSA,
		}
	}

	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if !ValidThreshold(cm.Threshold, len(ps)) {
		return fmt.Errorf("config: threshold %d is invalid", cm.Threshold)
	}

	// check that we are included
	if _, ok := ps[cm.ID]; !ok {
		return errors.New("config: no public data for this party")
	}

	// handle RID
	pr := make(map[party.ID]types.RID, len(cm.RID))
	for _, pm := range cm.RID {
		p := &ridMarshal{
			RID: types.EmptyRID(),
		}
		if err := cbor.Unmarshal(pm, p); err != nil {
			return fmt.Errorf("config: party %s: %w", p.ID, err)
		}
		if _, ok := pr[p.ID]; ok {
			return fmt.Errorf("config: party %s: duplicate entry", p.ID)
		}
		pr[p.ID] = p.RID
	}

	// verify number of parties w.r.t. threshold
	// want 0 ⩽ threshold ⩽ n-1
	if !ValidThreshold(cm.Threshold, len(ps)) {
		return fmt.Errorf("config: threshold %d is invalid", cm.Threshold)
	}

	// check that we are included
	if _, ok := ps[cm.ID]; !ok {
		return errors.New("config: no public data for this party")
	}

	*c = Config{
		Group:     c.Group,
		ID:        cm.ID,
		Threshold: cm.Threshold,
		ECDSA:     cm.ECDSA,
		RID:       pr,
		ChainKey:  cm.ChainKey,
		Public:    ps,
	}
	return nil
}
