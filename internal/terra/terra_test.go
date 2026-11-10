package terra

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func h(s string) []byte { b, _ := hex.DecodeString(s); return b }

// The Wii U messages are byte for byte from the M3 Quay capture (Terraria Wii U joining the relay host leg).
const (
	capHello = "010d01"
	capInfo  = "04190294361cf5835f0071bdb5431f67aad7fabe7801447108576969555465737441c58a34"
	capSlot0 = "0501000100f1ff"
	capEmpty = "05012f00"
	capDye   = "05013b00" // slot 59, empty
)

func tr(t *testing.T, msg []byte, from, to Platform) []byte {
	t.Helper()
	out, keep, err := Translate(msg, from, to)
	if err != nil || !keep {
		t.Fatalf("translate %x: keep=%v err=%v", msg, keep, err)
	}
	return out
}

func TestHello(t *testing.T) {
	if !bytes.Equal(Hello(WiiU, 1), h(capHello)) || !bytes.Equal(Hello(PS3, 1), h("010f01")) {
		t.Fatal("Hello builder")
	}
	if got := tr(t, h(capHello), WiiU, PS3); !bytes.Equal(got, h("010f01")) {
		t.Fatalf("wiiu->ps3 %x", got)
	}
	if got := tr(t, h("010f03"), PS3, WiiU); !bytes.Equal(got, h("010d03")) {
		t.Fatalf("ps3->wiiu %x", got)
	}
}

// slot 1, hair 3, male, difficulty 0 -> PS3 bits 0x0009, hair byte 3, dye and unknown 0, same colours/name/id.
func TestPlayerInfo(t *testing.T) {
	want := h("04" + "0900" + "030000" + capInfo[2+4:])
	got := tr(t, h(capInfo), WiiU, PS3)
	if !bytes.Equal(got, want) {
		t.Fatalf("wiiu->ps3\n got %x\nwant %x", got, want)
	}
	if back := tr(t, got, PS3, WiiU); !bytes.Equal(back, h(capInfo)) {
		t.Fatalf("round trip %x", back)
	}
	// Wii U bits with every packed field set survive the trip (hair 63, difficulty 2, flag, field 5).
	b := uint16(1 | 63<<3 | 1<<9 | 2<<10 | 1<<12 | 5<<13)
	in := append([]byte{4, byte(b), byte(b >> 8)}, h(capInfo)[3:]...)
	if back := tr(t, tr(t, in, WiiU, PS3), PS3, WiiU); !bytes.Equal(back, in) {
		t.Fatalf("full-field round trip %x vs %x", back, in)
	}
}

func TestInventory(t *testing.T) {
	for _, c := range []string{capSlot0, capEmpty} { // slots 0..58 pass untouched both ways
		if !bytes.Equal(tr(t, h(c), WiiU, PS3), h(c)) || !bytes.Equal(tr(t, h(c), PS3, WiiU), h(c)) {
			t.Fatalf("%s changed", c)
		}
	}
	if got := tr(t, h(capDye), WiiU, PS3); !bytes.Equal(got, h("05014000")) {
		t.Fatalf("dye wiiu->ps3 %x", got)
	}
	if got := tr(t, h("05014000"), PS3, WiiU); !bytes.Equal(got, h(capDye)) {
		t.Fatalf("dye ps3->wiiu %x", got)
	}
	if _, keep, _ := Translate(h("05013c00"), PS3, WiiU); keep { // slot 60: PS3 equipment, no Wii U peer
		t.Fatal("PS3 slot 60 kept")
	}
}

func TestPassThroughAndShort(t *testing.T) {
	m := h("0003") // ReqPlayerInfo-like, type 3
	if out, keep, _ := Translate(m, WiiU, PS3); !keep || !bytes.Equal(out, m) {
		t.Fatal("type 0 altered")
	}
	if _, _, err := Translate([]byte{1, 13}, WiiU, PS3); err == nil {
		t.Fatal("short hello accepted")
	}
}
