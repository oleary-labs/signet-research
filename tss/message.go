package tss

import (
	"github.com/fxamacker/cbor/v2"
)

// Message is a protocol message sent between parties during a session.
type Message struct {
	From      PartyID `cbor:"1,keyasint"`
	To        PartyID `cbor:"2,keyasint"` // empty = broadcast
	Round     int     `cbor:"3,keyasint"`
	Broadcast bool    `cbor:"4,keyasint"`
	Data      []byte  `cbor:"5,keyasint"` // round-specific CBOR payload
}

// msgWire is an alias used to break the MarshalBinary→cbor.Marshal recursion.
type msgWire Message

// MarshalBinary encodes the message using CBOR.
func (m *Message) MarshalBinary() ([]byte, error) {
	return cbor.Marshal((*msgWire)(m))
}

// UnmarshalBinary decodes the message from CBOR.
func (m *Message) UnmarshalBinary(data []byte) error {
	return cbor.Unmarshal(data, (*msgWire)(m))
}

// Network is the interface sessions use to communicate.
type Network interface {
	Send(msg *Message)
	Incoming() <-chan *Message
}
