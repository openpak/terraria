// Package terra translates the three Terraria messages whose layout differs between the Wii U build (console 1.08) and the
// patched PS3 build (NPEB01270 v01.12, console 1.09); the other 82 types pass through unchanged (prds#145, catalogue
// scratch/terraria-re/catalogue-ps3-0112.md). Messages are raw [u8 type][payload], little-endian, no length prefix.
//
// Evidence: the Wii U side of every layout is pinned by the M3 Quay capture (scratch/terraria-re/m3-quay-client-capture.jsonl).
// The PS3 side comes from the static decompile of the v01.12 EBOOT, not from a PS3 capture: Hello version 15 and the
// PlayerInfo/InventorySlot layouts are [C] there; the position and meaning of the three extra PlayerInfo bytes, the
// hair-in-a-byte mapping and the armour/dye slot split are [I] (catalogue "msg 4" / "msg 5"). One PS3 join capture settles them.
package terra

import "errors"

// Platform is the console build a message comes from or goes to.
type Platform int

const (
	WiiU Platform = iota
	PS3
)

const (
	msgHello      = 1
	msgPlayerInfo = 4
	msgInventory  = 5

	helloVersionWiiU = 13 // capture: 01 0d 01
	helloVersionPS3  = 15 // decompile: writer li 15 @0x21cfdc, server check cmpwi 15 @0x227340

	// PS3 inventory slot space: 0..47 inventory, 48..71 armour(16)+dye(8) [I]; Wii U: 0..47, 48..58 armour, 59..61 dye.
	wiiuDyeFirst, wiiuDyeLast = 59, 61
	ps3DyeFirst               = 64 // [I] armour[16] at 48..63, dye at 64..71
)

// Hello builds the client Hello [01][version][slot] for a platform's build.
func Hello(p Platform, slot byte) []byte {
	if p == PS3 {
		return []byte{msgHello, helloVersionPS3, slot}
	}
	return []byte{msgHello, helloVersionWiiU, slot}
}

var ErrShort = errors.New("terra: short message")

// Translate converts msg from one platform's layout to the other's. keep is false when the message has no peer on the
// target (a PS3 equipment slot the Wii U lacks). from == to returns msg as is.
func Translate(msg []byte, from, to Platform) (out []byte, keep bool, err error) {
	if from == to || len(msg) == 0 {
		return msg, true, nil
	}
	switch msg[0] {
	case msgHello:
		return hello(msg, to)
	case msgPlayerInfo:
		return playerInfo(msg, to)
	case msgInventory:
		return inventory(msg, to)
	}
	return msg, true, nil
}

// hello: [01][u8 version][u8 slot]; the host kicks a client whose version differs from its own build's.
func hello(m []byte, to Platform) ([]byte, bool, error) {
	if len(m) < 3 {
		return nil, false, ErrShort
	}
	out := append([]byte(nil), m...)
	out[1] = helloVersionWiiU
	if to == PS3 {
		out[1] = helloVersionPS3
	}
	return out, true, nil
}

// playerInfo: [04][u16 bits LE][...]. Wii U bits = slot&7 | hair(6)<<3 | male<<9 | difficulty(2)<<10 | flag<<12 | field(3)<<13,
// then 21 colour bytes, varint-string name, u32 id. PS3 bits = slot&7 | male<<3 | difficulty(2)<<4 | flag<<6 | field(9)<<7,
// then 3 bytes (hair, dye, unknown: [I]), then the same tail.
func playerInfo(m []byte, to Platform) ([]byte, bool, error) {
	if to == PS3 {
		if len(m) < 3 {
			return nil, false, ErrShort
		}
		b := uint16(m[1]) | uint16(m[2])<<8
		hair := byte(b >> 3 & 63)
		p := b&7 | (b>>9&0xf)<<3 | (b>>13&7)<<7 // male, difficulty, flag, then field
		out := []byte{msgPlayerInfo, byte(p), byte(p >> 8), hair, 0, 0}
		return append(out, m[3:]...), true, nil
	}
	if len(m) < 6 {
		return nil, false, ErrShort
	}
	b := uint16(m[1]) | uint16(m[2])<<8
	hair := uint16(m[3])
	if hair > 63 {
		hair = 63
	}
	p := b&7 | hair<<3 | (b>>3&0xf)<<9 | (b>>7&7)<<13 // field keeps its low 3 bits
	out := []byte{msgPlayerInfo, byte(p), byte(p >> 8)}
	return append(out, m[6:]...), true, nil
}

// inventory: [05][u8 player][u8 slot][...], only the slot number moves. 0..47 and 48..58 are shared; Wii U dye 59..61 is
// PS3 64..66; the rest of the PS3 equipment range has no Wii U peer.
func inventory(m []byte, to Platform) ([]byte, bool, error) {
	if len(m) < 3 {
		return nil, false, ErrShort
	}
	out := append([]byte(nil), m...)
	s := int(m[2])
	if to == PS3 {
		if s >= wiiuDyeFirst && s <= wiiuDyeLast {
			out[2] = byte(ps3DyeFirst + s - wiiuDyeFirst)
		}
		return out, true, nil
	}
	switch {
	case s >= ps3DyeFirst && s < ps3DyeFirst+3:
		out[2] = byte(wiiuDyeFirst + s - ps3DyeFirst)
	case s > 58:
		return nil, false, nil
	}
	return out, true, nil
}
