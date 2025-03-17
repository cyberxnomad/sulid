// Copyright 2016 The Oklog Authors
// Copyright 2024 @xray-bit
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sulid_test

import (
	"bytes"
	crand "crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	mrand "math/rand/v2"
	"strings"
	"testing"
	"testing/iotest"
	"testing/quick"
	"time"

	"github.com/cyberxnomad/sulid"
)

func newMathV2Rng(t time.Time) io.Reader {
	seed := [32]byte{}
	binary.LittleEndian.PutUint64(seed[24:], uint64(t.UnixNano()))

	return mrand.NewChaCha8(seed)
}

func ExampleSULID() {
	t := time.Unix(1000000, 0)
	entropy := sulid.Monotonic(newMathV2Rng(t), 0)
	fmt.Println(sulid.MustNew(sulid.Timestamp(t), entropy))
	// Output: 0000XSNJG05BSJZW5PA8
}

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("SULID", testSULID(func(ms uint64, e io.Reader) sulid.SULID {
		id, err := sulid.New(ms, e)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}))

	t.Run("Error", func(t *testing.T) {
		_, err := sulid.New(sulid.MaxTime()+1, nil)
		if got, want := err, sulid.ErrBigTime; got != want {
			t.Errorf("got err %v, want %v", got, want)
		}

		_, err = sulid.New(0, strings.NewReader(""))
		if got, want := err, io.EOF; got != want {
			t.Errorf("got err %v, want %v", got, want)
		}
	})
}

func TestMake(t *testing.T) {
	t.Parallel()
	id := sulid.Make()
	rt, err := sulid.Parse(id.String())
	if err != nil {
		t.Fatalf("parse %q: %v", id.String(), err)
	}
	if id != rt {
		t.Fatalf("%q != %q", id.String(), rt.String())
	}
}

func TestMustNew(t *testing.T) {
	t.Parallel()

	t.Run("SULID", testSULID(sulid.MustNew))

	t.Run("Panic", func(t *testing.T) {
		defer func() {
			if got, want := recover(), io.EOF; got != want {
				t.Errorf("panic with err %v, want %v", got, want)
			}
		}()
		_ = sulid.MustNew(0, strings.NewReader(""))
	})
}

func TestMustNewDefault(t *testing.T) {
	t.Parallel()

	t.Run("SULID", func(t *testing.T) {
		id := sulid.MustNewDefault(time.Now())
		rt, err := sulid.Parse(id.String())
		if err != nil {
			t.Fatalf("parse %q: %v", id.String(), err)
		}
		if id != rt {
			t.Fatalf("%q != %q", id.String(), rt.String())
		}
	})

	t.Run("Panic", func(t *testing.T) {
		defer func() {
			if got, want := recover(), sulid.ErrBigTime; got != want {
				t.Errorf("got panic %v, want %v", got, want)
			}
		}()
		_ = sulid.MustNewDefault(time.Time{})
	})
}

func TestMustParse(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		fn   func(string) sulid.SULID
	}{
		{"MustParse", sulid.MustParse},
		{"MustParseStrict", sulid.MustParseStrict},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if got, want := recover(), sulid.ErrDataSize; got != want {
					t.Errorf("got panic %v, want %v", got, want)
				}
			}()
			_ = tc.fn("")
		})

	}
}

func testSULID(mk func(uint64, io.Reader) sulid.SULID) func(*testing.T) {
	return func(t *testing.T) {
		want := sulid.SULID{0x0, 0x0, 0x0, 0x1, 0x86, 0xa0}
		if got := mk(1e5, nil); got != want { // optional entropy
			t.Errorf("\ngot  %#v\nwant %#v", got, want)
		}

		entropy := bytes.Repeat([]byte{0xFF}, 12)
		copy(want[6:], entropy)
		if got := mk(1e5, bytes.NewReader(entropy)); got != want {
			t.Errorf("\ngot  %#v\nwant %#v", got, want)
		}
	}
}

func TestRoundTrips(t *testing.T) {
	t.Parallel()

	prop := func(id sulid.SULID) bool {
		bin, err := id.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}

		txt, err := id.MarshalText()
		if err != nil {
			t.Fatal(err)
		}

		var a sulid.SULID
		if err = a.UnmarshalBinary(bin); err != nil {
			t.Fatal(err)
		}

		var b sulid.SULID
		if err = b.UnmarshalText(txt); err != nil {
			t.Fatal(err)
		}

		return id == a && b == id &&
			id == sulid.MustParse(id.String()) &&
			id == sulid.MustParseStrict(id.String())
	}

	err := quick.Check(prop, &quick.Config{MaxCount: 1e5})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMarshalingErrors(t *testing.T) {
	t.Parallel()

	var id sulid.SULID
	for _, tc := range []struct {
		name string
		fn   func([]byte) error
		err  error
	}{
		{"UnmarshalBinary", id.UnmarshalBinary, sulid.ErrDataSize},
		{"UnmarshalText", id.UnmarshalText, sulid.ErrDataSize},
		{"MarshalBinaryTo", id.MarshalBinaryTo, sulid.ErrBufferSize},
		{"MarshalTextTo", id.MarshalTextTo, sulid.ErrBufferSize},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := tc.fn([]byte{}), tc.err; got != want {
				t.Errorf("got err %v, want %v", got, want)
			}
		})

	}
}

func TestParseStrictInvalidCharacters(t *testing.T) {
	t.Parallel()

	type testCase struct {
		name  string
		input string
	}
	testCases := []testCase{}
	base := "0000XSNJG055WMAVS5Z8"
	for i := 0; i < sulid.EncodedSize; i++ {
		testCases = append(testCases, testCase{
			name:  fmt.Sprintf("Invalid 0xFF at index %d", i),
			input: base[:i] + "\xff" + base[i+1:],
		})
		testCases = append(testCases, testCase{
			name:  fmt.Sprintf("Invalid 0x00 at index %d", i),
			input: base[:i] + "\x00" + base[i+1:],
		})
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sulid.ParseStrict(tt.input)
			if err != sulid.ErrInvalidCharacters {
				t.Errorf("Parse(%q): got err %v, want %v", tt.input, err, sulid.ErrInvalidCharacters)
			}
		})
	}
}

func TestAlizainCompatibility(t *testing.T) {
	t.Parallel()

	ts := uint64(1469918176385)
	got := sulid.MustNew(ts, bytes.NewReader(make([]byte, 12)))
	want := sulid.MustParse("01ARYZ6S410000000000")
	if got != want {
		t.Fatalf("with time=%d, got %q, want %q", ts, got, want)
	}
}

func TestEncoding(t *testing.T) {
	t.Parallel()

	enc := make(map[rune]bool, len(sulid.Encoding))
	for _, r := range sulid.Encoding {
		enc[r] = true
	}

	prop := func(id sulid.SULID) bool {
		for _, r := range id.String() {
			if !enc[r] {
				return false
			}
		}
		return true
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1e5}); err != nil {
		t.Fatal(err)
	}
}

func TestLexicographicalOrder(t *testing.T) {
	t.Parallel()

	prop := func(a, b sulid.SULID) bool {
		t1, t2 := a.Time(), b.Time()
		s1, s2 := a.String(), b.String()
		ord := bytes.Compare(a[:], b[:])
		return t1 == t2 ||
			(t1 > t2 && s1 > s2 && ord == +1) ||
			(t1 < t2 && s1 < s2 && ord == -1)
	}

	top := sulid.MustNew(sulid.MaxTime(), nil)
	for i := 0; i < 10; i++ { // test upper boundary state space
		next := sulid.MustNew(top.Time()-1, nil)
		if !prop(top, next) {
			t.Fatalf("bad lexicographical order: (%v, %q) > (%v, %q) == false",
				top.Time(), top,
				next.Time(), next,
			)
		}
		top = next
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1e6}); err != nil {
		t.Fatal(err)
	}
}

func TestCaseInsensitivity(t *testing.T) {
	t.Parallel()

	upper := func(id sulid.SULID) (out sulid.SULID) {
		return sulid.MustParse(strings.ToUpper(id.String()))
	}

	lower := func(id sulid.SULID) (out sulid.SULID) {
		return sulid.MustParse(strings.ToLower(id.String()))
	}

	err := quick.CheckEqual(upper, lower, nil)
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRobustness(t *testing.T) {
	t.Parallel()

	cases := [][]byte{
		{0x1, 0xc0, 0x73, 0x62, 0x4a, 0xaf, 0x39, 0x78, 0x51, 0x4e, 0xf8, 0x44, 0x3b,
			0xb2, 0xa8, 0x59, 0xc7, 0x5f, 0xc3, 0xcc},
	}

	for _, tc := range cases {
		if _, err := sulid.Parse(string(tc)); err != nil {
			t.Error(err)
		}
	}

	prop := func(s [20]byte) (ok bool) {
		defer func() {
			if err := recover(); err != nil {
				t.Error(err)
				ok = false
			}
		}()

		// quick.Check doesn't constrain input,
		// so we need to do so artificially.
		if s[0] > '7' {
			s[0] %= '7'
		}

		var err error
		if _, err = sulid.Parse(string(s[:])); err != nil {
			t.Error(err)
		}

		return err == nil
	}

	err := quick.Check(prop, &quick.Config{MaxCount: 1e4})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNow(t *testing.T) {
	t.Parallel()

	before := sulid.Now()
	after := sulid.Timestamp(time.Now().UTC().Add(time.Millisecond))

	if before >= after {
		t.Fatalf("clock went mad: before %v, after %v", before, after)
	}
}

func TestTimestamp(t *testing.T) {
	t.Parallel()

	tm := time.Unix(1, 1000) // will be truncated
	if got, want := sulid.Timestamp(tm), uint64(1000); got != want {
		t.Errorf("for %v, got %v, want %v", tm, got, want)
	}

	mt := sulid.MaxTime()
	dt := time.Unix(int64(mt/1000), int64((mt%1000)*1000000)).Truncate(time.Millisecond)
	ts := sulid.Timestamp(dt)
	if got, want := ts, mt; got != want {
		t.Errorf("got timestamp %d, want %d", got, want)
	}
}

func TestTime(t *testing.T) {
	t.Parallel()

	original := time.Now()
	diff := original.Sub(sulid.Time(sulid.Timestamp(original)))
	if diff >= time.Millisecond {
		t.Errorf("difference between original and recovered time (%d) greater"+
			"than a millisecond", diff)
	}
}

func TestTimestampRoundTrips(t *testing.T) {
	t.Parallel()

	prop := func(ts uint64) bool {
		return ts == sulid.Timestamp(sulid.Time(ts))
	}

	err := quick.Check(prop, &quick.Config{MaxCount: 1e5})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSULIDTime(t *testing.T) {
	t.Parallel()

	maxTime := sulid.MaxTime()

	var id sulid.SULID
	if got, want := id.SetTime(maxTime+1), sulid.ErrBigTime; got != want {
		t.Errorf("got err %v, want %v", got, want)
	}

	for range int(1e6) {
		ms := uint64(mrand.Int64N(int64(maxTime)))

		var id sulid.SULID
		if err := id.SetTime(ms); err != nil {
			t.Fatal(err)
		}

		if got, want := id.Time(), ms; got != want {
			t.Fatalf("\nfor %v:\ngot  %v\nwant %v", id, got, want)
		}
	}
}

func TestSULIDTimestamp(t *testing.T) {
	t.Parallel()

	{
		id := sulid.Make()
		ts := id.Timestamp()
		tt := sulid.Time(id.Time())
		if ts != tt {
			t.Errorf("id.Timestamp() %s != sulid.Time(id.Time()) %s", ts, tt)
		}
	}

	{
		now := time.Now()
		id := sulid.MustNew(sulid.Timestamp(now), sulid.DefaultEntropy())
		if want, have := now.Truncate(time.Millisecond), id.Timestamp(); want != have {
			t.Errorf("Timestamp: want %v, have %v", want, have)
		}
	}
}

func TestZero(t *testing.T) {
	t.Parallel()

	var id sulid.SULID
	if ok := id.IsZero(); !ok {
		t.Error(".IsZero: must return true for zero-value SULIDs, have false")
	}

	id = sulid.MustNew(sulid.Now(), sulid.DefaultEntropy())
	if ok := id.IsZero(); ok {
		t.Error(".IsZero: must return false for non-zero-value SULIDs, have true")
	}
}

func TestEntropy(t *testing.T) {
	t.Parallel()

	var id sulid.SULID
	if got, want := id.SetEntropy([]byte{}), sulid.ErrDataSize; got != want {
		t.Errorf("got err %v, want %v", got, want)
	}

	prop := func(e [6]byte) bool {
		var id sulid.SULID
		if err := id.SetEntropy(e[:]); err != nil {
			t.Fatalf("got err %v", err)
		}

		got, want := id.Entropy(), e[:]
		eq := bytes.Equal(got, want)
		if !eq {
			t.Errorf("\n(!= %v\n    %v)", got, want)
		}

		return eq
	}

	if err := quick.Check(prop, nil); err != nil {
		t.Fatal(err)
	}
}

func TestEntropyRead(t *testing.T) {
	t.Parallel()

	prop := func(e [6]byte) bool {
		flakyReader := iotest.HalfReader(bytes.NewReader(e[:]))

		id, err := sulid.New(sulid.Now(), flakyReader)
		if err != nil {
			t.Fatalf("got err %v", err)
		}

		got, want := id.Entropy(), e[:]
		eq := bytes.Equal(got, want)
		if !eq {
			t.Errorf("\n(!= %v\n    %v)", got, want)
		}

		return eq
	}

	if err := quick.Check(prop, &quick.Config{MaxCount: 1e4}); err != nil {
		t.Fatal(err)
	}
}

func TestCompare(t *testing.T) {
	t.Parallel()

	a := func(a, b sulid.SULID) int {
		return strings.Compare(a.String(), b.String())
	}

	b := func(a, b sulid.SULID) int {
		return a.Compare(b)
	}

	err := quick.CheckEqual(a, b, &quick.Config{MaxCount: 1e5})
	if err != nil {
		t.Error(err)
	}
}

func TestOverflowHandling(t *testing.T) {
	t.Parallel()

	for s, want := range map[string]error{
		"00000000000000000000": nil,
		"70000000000000000000": nil,
		"7ZZZZZZZZZZZZZZZZZZZ": nil,
		"80000000000000000000": sulid.ErrOverflow,
		"80000000000000000001": sulid.ErrOverflow,
		"ZZZZZZZZZZZZZZZZZZZZ": sulid.ErrOverflow,
	} {
		if _, have := sulid.Parse(s); want != have {
			t.Errorf("%s: want error %v, have %v", s, want, have)
		}
	}
}

func TestScan(t *testing.T) {
	id := sulid.MustNew(123, crand.Reader)

	for _, tc := range []struct {
		name string
		in   interface{}
		out  sulid.SULID
		err  error
	}{
		{"string", id.String(), id, nil},
		{"bytes", id[:], id, nil},
		{"nil", nil, sulid.SULID{}, nil},
		{"other", 44, sulid.SULID{}, sulid.ErrScanValue},
	} {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out sulid.SULID
			err := out.Scan(tc.in)
			if got, want := out, tc.out; got.Compare(want) != 0 {
				t.Errorf("got SULID %s, want %s", got, want)
			}

			if got, want := fmt.Sprint(err), fmt.Sprint(tc.err); got != want {
				t.Errorf("got err %q, want %q", got, want)
			}
		})
	}
}

func TestMonotonic(t *testing.T) {
	now := time.Now()
	for _, e := range []struct {
		name string
		mk   func() io.Reader
	}{
		{"cryptorand", func() io.Reader { return crand.Reader }},
		{"mathrand", func() io.Reader { return newMathV2Rng(now) }},
	} {
		for _, inc := range []uint32{
			0,
			1,
			2,
			math.MaxUint8 + 1,
			math.MaxUint16 + 1,
		} {
			inc := inc
			entropy := sulid.Monotonic(e.mk(), inc)

			t.Run(fmt.Sprintf("entropy=%s/inc=%d", e.name, inc), func(t *testing.T) {
				t.Parallel()

				var prev sulid.SULID
				for i := 0; i < 10000; i++ {
					next, err := sulid.New(123, entropy)
					if err != nil {
						t.Fatal(err)
					}

					if prev.Compare(next) >= 0 {
						t.Fatalf("prev: %v %v > next: %v %v",
							prev.Time(), prev.Entropy(), next.Time(), next.Entropy())
					}

					prev = next
				}
			})
		}
	}
}

func TestMonotonicOverflow(t *testing.T) {
	t.Parallel()

	entropy := sulid.Monotonic(
		io.MultiReader(
			bytes.NewReader(bytes.Repeat([]byte{0xFF}, 10)), // Entropy for first SULID
			crand.Reader, // Following random entropy
		),
		0,
	)

	prev, err := sulid.New(0, entropy)
	if err != nil {
		t.Fatal(err)
	}

	next, err := sulid.New(prev.Time(), entropy)
	if have, want := err, sulid.ErrMonotonicOverflow; have != want {
		t.Errorf("have sulid: %v %v err: %v, want err: %v",
			next.Time(), next.Entropy(), have, want)
	}
}

func TestMonotonicSafe(t *testing.T) {
	t.Parallel()

	var (
		rng  = newMathV2Rng(time.Now())
		safe = &sulid.LockedMonotonicReader{MonotonicReader: sulid.Monotonic(rng, 0)}
		t0   = sulid.Timestamp(time.Now())
	)

	errs := make(chan error, 100)
	for i := 0; i < cap(errs); i++ {
		go func() {
			u0 := sulid.MustNew(t0, safe)
			u1 := u0
			for j := 0; j < 1024; j++ {
				u0, u1 = u1, sulid.MustNew(t0, safe)
				if u0.String() >= u1.String() {
					errs <- fmt.Errorf(
						"%s (%d %x) >= %s (%d %x)",
						u0.String(), u0.Time(), u0.Entropy(),
						u1.String(), u1.Time(), u1.Entropy(),
					)
					return
				}
			}
			errs <- nil
		}()
	}

	for i := 0; i < cap(errs); i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestSULID_Bytes(t *testing.T) {
	tt := time.Unix(1000000, 0)
	entropy := sulid.Monotonic(newMathV2Rng(tt), 0)
	id := sulid.MustNew(sulid.Timestamp(tt), entropy)
	bid := id.Bytes()
	bid[len(bid)-1]++
	if bytes.Equal(id.Bytes(), bid) {
		t.Error("Bytes() returned a reference to sulid underlying array!")
	}
}

func BenchmarkNew(b *testing.B) {
	benchmarkMakeSULID(b, func(timestamp uint64, entropy io.Reader) {
		_, _ = sulid.New(timestamp, entropy)
	})
}

func BenchmarkMustNew(b *testing.B) {
	benchmarkMakeSULID(b, func(timestamp uint64, entropy io.Reader) {
		_ = sulid.MustNew(timestamp, entropy)
	})
}

func benchmarkMakeSULID(b *testing.B, f func(uint64, io.Reader)) {
	b.ReportAllocs()
	b.SetBytes(int64(len(sulid.SULID{})))

	rng := newMathV2Rng(time.Now())

	for _, tc := range []struct {
		name       string
		timestamps []uint64
		entropy    io.Reader
	}{
		{"WithCrypoEntropy", []uint64{123}, crand.Reader},
		{"WithEntropy", []uint64{123}, rng},
		{"WithMonotonicEntropy_SameTimestamp_Inc0", []uint64{123}, sulid.Monotonic(rng, 0)},
		{"WithMonotonicEntropy_DifferentTimestamp_Inc0", []uint64{122, 123}, sulid.Monotonic(rng, 0)},
		{"WithMonotonicEntropy_SameTimestamp_Inc1", []uint64{123}, sulid.Monotonic(rng, 1)},
		{"WithMonotonicEntropy_DifferentTimestamp_Inc1", []uint64{122, 123}, sulid.Monotonic(rng, 1)},
		{"WithCryptoMonotonicEntropy_SameTimestamp_Inc1", []uint64{123}, sulid.Monotonic(crand.Reader, 1)},
		{"WithCryptoMonotonicEntropy_DifferentTimestamp_Inc1", []uint64{122, 123}, sulid.Monotonic(crand.Reader, 1)},
		{"WithoutEntropy", []uint64{123}, nil},
	} {
		tc := tc
		b.Run(tc.name, func(b *testing.B) {
			b.StopTimer()
			b.ResetTimer()
			b.StartTimer()
			for i := 0; i < b.N; i++ {
				f(tc.timestamps[i%len(tc.timestamps)], tc.entropy)
			}
		})
	}
}

func BenchmarkParse(b *testing.B) {
	const s = "0000XSNJG055WMAVS5Z8"
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		_, _ = sulid.Parse(s)
	}
}

func BenchmarkParseStrict(b *testing.B) {
	const s = "0000XSNJG055WMAVS5Z8"
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		_, _ = sulid.ParseStrict(s)
	}
}

func BenchmarkMustParse(b *testing.B) {
	const s = "0000XSNJG055WMAVS5Z8"
	b.SetBytes(int64(len(s)))
	for i := 0; i < b.N; i++ {
		_ = sulid.MustParse(s)
	}
}

func BenchmarkString(b *testing.B) {
	entropy := newMathV2Rng(time.Now())
	id := sulid.MustNew(123456, entropy)
	b.SetBytes(int64(len(id)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.String()
	}
}

func BenchmarkMarshal(b *testing.B) {
	entropy := newMathV2Rng(time.Now())
	buf := make([]byte, sulid.EncodedSize)
	id := sulid.MustNew(123456, entropy)

	b.Run("Text", func(b *testing.B) {
		b.SetBytes(int64(len(id)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = id.MarshalText()
		}
	})

	b.Run("TextTo", func(b *testing.B) {
		b.SetBytes(int64(len(id)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = id.MarshalTextTo(buf)
		}
	})

	b.Run("Binary", func(b *testing.B) {
		b.SetBytes(int64(len(id)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _ = id.MarshalBinary()
		}
	})

	b.Run("BinaryTo", func(b *testing.B) {
		b.SetBytes(int64(len(id)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = id.MarshalBinaryTo(buf)
		}
	})
}

func BenchmarkUnmarshal(b *testing.B) {
	var id sulid.SULID
	s := "0000XSNJG055WMAVS5Z8"
	txt := []byte(s)
	bin, _ := sulid.MustParse(s).MarshalBinary()

	b.Run("Text", func(b *testing.B) {
		b.SetBytes(int64(len(txt)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = id.UnmarshalText(txt)
		}
	})

	b.Run("Binary", func(b *testing.B) {
		b.SetBytes(int64(len(bin)))
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_ = id.UnmarshalBinary(bin)
		}
	})
}

func BenchmarkNow(b *testing.B) {
	b.SetBytes(8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sulid.Now()
	}
}

func BenchmarkTimestamp(b *testing.B) {
	now := time.Now()
	b.SetBytes(8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sulid.Timestamp(now)
	}
}

func BenchmarkTime(b *testing.B) {
	id := sulid.MustNew(123456789, nil)
	b.SetBytes(8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.Time()
	}
}

func BenchmarkSetTime(b *testing.B) {
	var id sulid.SULID
	b.SetBytes(8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.SetTime(123456789)
	}
}

func BenchmarkEntropy(b *testing.B) {
	id := sulid.MustNew(0, strings.NewReader("ABCDEFGHIJKLMNOP"))
	b.SetBytes(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.Entropy()
	}
}

func BenchmarkSetEntropy(b *testing.B) {
	var id sulid.SULID
	e := []byte("ABCDEFGHIJKLMNOP")
	b.SetBytes(10)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.SetEntropy(e)
	}
}

func BenchmarkCompare(b *testing.B) {
	id, other := sulid.MustNew(12345, nil), sulid.MustNew(54321, nil)
	b.SetBytes(int64(len(id) * 2))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = id.Compare(other)
	}
}
