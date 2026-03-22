package tss

import "fmt"

// Reshare returns the starting Round for a key reshare protocol.
// Full committee resharing (new parties, threshold changes) is planned as a
// follow-on milestone. The protocol will use the standard Lagrange-weighting
// technique (Herzberg et al. 1995) on top of Feldman VSS — the same math as
// the lss reshare protocol but using FROST-compatible key shares.
func Reshare(cfg *Config, selfID PartyID, oldParties []PartyID, newParties []PartyID, newThreshold int) Round {
	return &errRound{err: fmt.Errorf("reshare: not yet implemented; planned as follow-on milestone")}
}
