package main

import (
	cryptorand "crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	mathrand "math/rand/v2"
	"os"
	"strings"
	"time"

	"github.com/cyberxnomad/sulid"
)

const (
	defaultms = "Mon Jan 02 15:04:05.999 MST 2006"
	rfc3339ms = "2006-01-02T15:04:05.000Z07:00"
)

var (
	// parse flags
	formatFlag string
	localFlag  bool

	// generation flags
	quickFlag   bool
	zeroFlag    bool
	monoticFlag bool
	numberFlag  uint
)

func init() {
	// parse flags
	flag.StringVar(&formatFlag, "f", "default", "when parsing, show times in this format: default, rfc3339, unix, ms")
	flag.BoolVar(&localFlag, "l", false, "when parsing, show local time instead of UTC")

	// generation flags
	flag.BoolVar(&quickFlag, "q", false, "when generating, use non-crypto-grade entropy")
	flag.BoolVar(&zeroFlag, "z", false, "when generating, fix entropy to all-zeroes")
	flag.BoolVar(&monoticFlag, "m", true, "when generating, use monotonically increasing")
	flag.UintVar(&numberFlag, "n", 1, "when generating, specify the quantity to be generated")
}

func main() {
	flag.Parse()
	args := flag.Args()

	var formatFunc func(time.Time) string
	switch strings.ToLower(formatFlag) {
	case "default":
		formatFunc = func(t time.Time) string { return t.Format(defaultms) }
	case "rfc3339":
		formatFunc = func(t time.Time) string { return t.Format(rfc3339ms) }
	case "unix":
		formatFunc = func(t time.Time) string { return fmt.Sprint(t.Unix()) }
	case "ms":
		formatFunc = func(t time.Time) string { return fmt.Sprint(t.UnixNano() / 1e6) }
	default:
		fmt.Fprintf(os.Stderr, "invalid -f %s\n", formatFlag)
		os.Exit(1)
	}

	switch len(args) {
	case 0:
		generate(quickFlag, zeroFlag, monoticFlag, numberFlag)
	default:
		parse(args[0], localFlag, formatFunc)
	}
}

func generate(quick, zero, mono bool, num uint) {
	entropy := cryptorand.Reader
	if quick {
		seed := [32]byte{}
		binary.LittleEndian.PutUint64(seed[24:], uint64(time.Now().UnixNano()))

		entropy = mathrand.NewChaCha8(seed)
	}
	if zero {
		entropy = zeroReader{}
	}

	if mono {
		entropy = &sulid.LockedMonotonicReader{MonotonicReader: sulid.Monotonic(entropy, 0)}
	}

	for range num {
		id, err := sulid.New(sulid.Timestamp(time.Now()), entropy)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stdout, "%s\n", id)
	}
}

func parse(s string, local bool, f func(time.Time) string) {
	id, err := sulid.ParseStrict(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	t := sulid.Time(id.Time())
	if !local {
		t = t.UTC()
	}
	fmt.Fprintf(os.Stderr, "%s\n", f(t))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}
