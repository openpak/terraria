// Command terraria is OpenPak's Terraria service (common/terraria, prds#157). Today it holds the PIA probe, the start of the
// relay's Wii U leg (prds#145): `terraria probe` listens where a Wii U is told the host is, decrypts what it sends with the
// session key and writes every packet to a capture file.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "probe" {
		if err := probe(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "probe:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "join" {
		if err := join(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "join:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "usage: terraria probe|join ...")
	os.Exit(2)
}
