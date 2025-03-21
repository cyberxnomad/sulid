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

package sulid

import (
	"bufio"
	"bytes"
	"database/sql/driver"
	"encoding/binary"
	"errors"
	"io"
	"math"
	"math/bits"
	"math/rand/v2"
	"sync"
	"time"
)

/*
A SULID is a 12 byte Universally Unique Lexicographically Sortable Identifier

	The components are encoded as 12 octets.
	Each component is encoded with the MSB first (network byte order).

	0                   1                   2                   3
	0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                      32_bit_uint_time_high                    |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|     16_bit_uint_time_low      |       16_bit_uint_random      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	|                       32_bit_uint_random                      |
	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
type SULID [12]byte

var (
	// ErrDataSize is returned when parsing or unmarshaling SULIDs with the wrong
	// data size.
	ErrDataSize = errors.New("sulid: bad data size when unmarshaling")

	// ErrInvalidCharacters is returned when parsing or unmarshaling SULIDs with
	// invalid Base32 encodings.
	ErrInvalidCharacters = errors.New("sulid: bad data characters when unmarshaling")

	// ErrBufferSize is returned when marshalling SULIDs to a buffer of insufficient
	// size.
	ErrBufferSize = errors.New("sulid: bad buffer size when marshaling")

	// ErrBigTime is returned when constructing a SULID with a time that is larger
	// than MaxTime.
	ErrBigTime = errors.New("sulid: time too big")

	// ErrOverflow is returned when unmarshaling a SULID whose first character is
	// larger than 7, thereby exceeding the valid bit depth of 128.
	ErrOverflow = errors.New("sulid: overflow when unmarshaling")

	// ErrMonotonicOverflow is returned by a Monotonic entropy source when
	// incrementing the previous SULID's entropy bytes would result in overflow.
	ErrMonotonicOverflow = errors.New("sulid: monotonic entropy overflow")

	// ErrScanValue is returned when the value passed to scan cannot be unmarshaled
	// into the SULID.
	ErrScanValue = errors.New("sulid: source value must be a string or byte slice")

	// Zero is a zero-value SULID.
	Zero SULID
)

// MonotonicReader is an interface that should yield monotonically increasing
// entropy into the provided slice for all calls with the same ms parameter. If
// a MonotonicReader is provided to the New constructor, its MonotonicRead
// method will be used instead of Read.
type MonotonicReader interface {
	io.Reader
	MonotonicRead(ms uint64, p []byte) error
}

// New returns a SULID with the given Unix milliseconds timestamp and an
// optional entropy source. Use the Timestamp function to convert
// a time.Time to Unix milliseconds.
//
// ErrBigTime is returned when passing a timestamp bigger than MaxTime.
// Reading from the entropy source may also return an error.
//
// Safety for concurrent use is only dependent on the safety of the
// entropy source.
func New(ms uint64, entropy io.Reader) (id SULID, err error) {
	if err = id.SetTime(ms); err != nil {
		return id, err
	}

	switch e := entropy.(type) {
	case nil:
		return id, err
	case MonotonicReader:
		err = e.MonotonicRead(ms, id[6:])
	default:
		_, err = io.ReadFull(e, id[6:])
	}

	return id, err
}

// MustNew is a convenience function equivalent to New that panics on failure
// instead of returning an error.
func MustNew(ms uint64, entropy io.Reader) SULID {
	id, err := New(ms, entropy)
	if err != nil {
		panic(err)
	}
	return id
}

// MustNewDefault is a convenience function equivalent to MustNew with
// DefaultEntropy as the entropy. It may panic if the given time.Time is too
// large or too small.
func MustNewDefault(t time.Time) SULID {
	return MustNew(Timestamp(t), defaultEntropy)
}

var defaultEntropy = func() io.Reader {
	seed := [32]byte{}
	binary.LittleEndian.PutUint64(seed[24:], uint64(time.Now().UnixNano()))

	rng := rand.NewChaCha8(seed)

	return &LockedMonotonicReader{MonotonicReader: Monotonic(rng, 0)}
}()

// DefaultEntropy returns a thread-safe per process monotonically increasing
// entropy source.
func DefaultEntropy() io.Reader {
	return defaultEntropy
}

// Make returns a SULID with the current time in Unix milliseconds and
// monotonically increasing entropy for the same millisecond.
// It is safe for concurrent use, leveraging a sync.Pool underneath for minimal
// contention.
func Make() (id SULID) {
	// NOTE: MustNew can't panic since DefaultEntropy never returns an error.
	return MustNew(Now(), defaultEntropy)
}

// Parse parses an encoded SULID, returning an error in case of failure.
//
// ErrDataSize is returned if the len(sulid) is different from an encoded
// SULID's length. Invalid encodings produce undefined SULIDs. For a version that
// returns an error instead, see ParseStrict.
func Parse(sulid string) (id SULID, err error) {
	return id, parse([]byte(sulid), false, &id)
}

// ParseStrict parses an encoded SULID, returning an error in case of failure.
//
// It is like Parse, but additionally validates that the parsed SULID consists
// only of valid base32 characters. It is slightly slower than Parse.
//
// ErrDataSize is returned if the len(sulid) is different from an encoded
// SULID's length. Invalid encodings return ErrInvalidCharacters.
func ParseStrict(sulid string) (id SULID, err error) {
	return id, parse([]byte(sulid), true, &id)
}

func parse(v []byte, strict bool, id *SULID) error {
	// Check if a base32 encoded SULID is the right length.
	if len(v) != EncodedSize {
		return ErrDataSize
	}

	// Use an optimized unrolled loop to decode a base32 ULID.
	// The MSB(Most Significant Bit) is reserved for detecting invalid indexes.
	//
	// For example, in normal case, the bit layout of uint64(dec[v[0]])<<45 becomes:
	//
	//     | 63 | 62 | 61 | 60 | 59 | 58 | 57 | 56 | 55 | 54 | 53 | 52 | 51 | 50 | 49 | 48 | 47 | 46 | 45 | 44 | ... |
	//     |----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|-----|
	//     |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  0 |  x |  x |  x |  x |  x |  0 | ... |
	//
	// and the MSB is set to 0.
	//
	// If the character is not part of the base32 character set, the layout becomes:
	//
	//     | 63 | 62 | 61 | 60 | 59 | 58 | 57 | 56 | 55 | 54 | 53 | 52 | 51 | 50 | 49 | 48 | 47 | 46 | 45 | 44 | ... |
	//     |----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|----|-----|
	//     |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  1 |  0 | ... |
	//
	// and the MSB is set to 1.
	//
	// Reference: https://github.com/oklog/ulid/pull/116
	// Original: @shogo82148
	h := uint64(dec[v[0]])<<45 |
		uint64(dec[v[1]])<<40 |
		uint64(dec[v[2]])<<35 |
		uint64(dec[v[3]])<<30 |
		uint64(dec[v[4]])<<25 |
		uint64(dec[v[5]])<<20 |
		uint64(dec[v[6]])<<15 |
		uint64(dec[v[7]])<<10 |
		uint64(dec[v[8]])<<5 |
		uint64(dec[v[9]])

	l := uint64(dec[v[10]])<<45 |
		uint64(dec[v[11]])<<40 |
		uint64(dec[v[12]])<<35 |
		uint64(dec[v[13]])<<30 |
		uint64(dec[v[14]])<<25 |
		uint64(dec[v[15]])<<20 |
		uint64(dec[v[16]])<<15 |
		uint64(dec[v[17]])<<10 |
		uint64(dec[v[18]])<<5 |
		uint64(dec[v[19]])
	if strict && (h|l)&(1<<63) != 0 {
		return ErrInvalidCharacters
	}

	// Check if the first character in a base32 encoded SULID will overflow. This
	// happens because the base32 representation encodes 130 bits, while the
	// SULID is only 128 bits.
	//
	// See https://github.com/oklog/sulid/issues/9 for details.
	if v[0] > '7' {
		return ErrOverflow
	}

	// Use an optimized unrolled loop (from https://github.com/RobThree/NUlid)
	// to decode a base32 SULID.

	// 6 bytes timestamp (48 bits)
	(*id)[0] = byte(h >> 40)
	(*id)[1] = byte(h >> 32)
	(*id)[2] = byte(h >> 24)
	(*id)[3] = byte(h >> 16)
	(*id)[4] = byte(h >> 8)
	(*id)[5] = byte(h)

	// 6 bytes of entropy (48 bits)
	(*id)[6] = byte(l >> 40)
	(*id)[7] = byte(l >> 32)
	(*id)[8] = byte(l >> 24)
	(*id)[9] = byte(l >> 16)
	(*id)[10] = byte(l >> 8)
	(*id)[11] = byte(l)

	return nil
}

// MustParse is a convenience function equivalent to Parse that panics on failure
// instead of returning an error.
func MustParse(sulid string) SULID {
	id, err := Parse(sulid)
	if err != nil {
		panic(err)
	}
	return id
}

// MustParseStrict is a convenience function equivalent to ParseStrict that
// panics on failure instead of returning an error.
func MustParseStrict(sulid string) SULID {
	id, err := ParseStrict(sulid)
	if err != nil {
		panic(err)
	}
	return id
}

// Bytes returns bytes slice representation of SULID.
func (id SULID) Bytes() []byte {
	return id[:]
}

// String returns a lexicographically sortable string encoded SULID
// (20 characters, non-standard base 32) e.g. 01AN4Z07BY79KA1307SR9X4MV3.
// Format: tttttttttteeeeeeeeee where t is time and e is entropy.
func (id SULID) String() string {
	sulid := make([]byte, EncodedSize)
	_ = id.MarshalTextTo(sulid)
	return string(sulid)
}

// MarshalBinary implements the encoding.BinaryMarshaler interface by
// returning the SULID as a byte slice.
func (id SULID) MarshalBinary() ([]byte, error) {
	sulid := make([]byte, len(id))
	return sulid, id.MarshalBinaryTo(sulid)
}

// MarshalBinaryTo writes the binary encoding of the SULID to the given buffer.
// ErrBufferSize is returned when the len(dst) != 12.
func (id SULID) MarshalBinaryTo(dst []byte) error {
	if len(dst) != len(id) {
		return ErrBufferSize
	}

	copy(dst, id[:])
	return nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface by
// copying the passed data and converting it to a SULID. ErrDataSize is
// returned if the data length is different from SULID length.
func (id *SULID) UnmarshalBinary(data []byte) error {
	if len(data) != len(*id) {
		return ErrDataSize
	}

	copy((*id)[:], data)
	return nil
}

// Encoding is the base 32 encoding alphabet used in SULID strings.
const Encoding = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// MarshalText implements the encoding.TextMarshaler interface by
// returning the string encoded SULID.
func (id SULID) MarshalText() ([]byte, error) {
	sulid := make([]byte, EncodedSize)
	return sulid, id.MarshalTextTo(sulid)
}

// MarshalTextTo writes the SULID as a string to the given buffer.
// ErrBufferSize is returned when the len(dst) != 20.
func (id SULID) MarshalTextTo(dst []byte) error {
	if len(dst) != EncodedSize {
		return ErrBufferSize
	}

	// Optimized unrolled loop ahead.
	//
	// Reference: https://github.com/oklog/ulid/pull/115
	// Original: @shogo82148

	h := uint64(id[0])<<40 |
		uint64(id[1])<<32 |
		uint64(id[2])<<24 |
		uint64(id[3])<<16 |
		uint64(id[4])<<8 |
		uint64(id[5])

	l := uint64(id[6])<<40 |
		uint64(id[7])<<32 |
		uint64(id[8])<<24 |
		uint64(id[9])<<16 |
		uint64(id[10])<<8 |
		uint64(id[11])

	// 10 byte timestamp
	dst[0] = Encoding[(h>>45)&0x1F]
	dst[1] = Encoding[(h>>40)&0x1F]
	dst[2] = Encoding[(h>>35)&0x1F]
	dst[3] = Encoding[(h>>30)&0x1F]
	dst[4] = Encoding[(h>>25)&0x1F]
	dst[5] = Encoding[(h>>20)&0x1F]
	dst[6] = Encoding[(h>>15)&0x1F]
	dst[7] = Encoding[(h>>10)&0x1F]
	dst[8] = Encoding[(h>>5)&0x1F]
	dst[9] = Encoding[(h)&0x1F]

	// 10 bytes of entropy
	dst[10] = Encoding[(l>>45)&0x1F]
	dst[11] = Encoding[(l>>40)&0x1F]
	dst[12] = Encoding[(l>>35)&0x1F]
	dst[13] = Encoding[(l>>30)&0x1F]
	dst[14] = Encoding[(l>>25)&0x1F]
	dst[15] = Encoding[(l>>20)&0x1F]
	dst[16] = Encoding[(l>>15)&0x1F]
	dst[17] = Encoding[(l>>10)&0x1F]
	dst[18] = Encoding[(l>>5)&0x1F]
	dst[19] = Encoding[(l)&0x1F]

	return nil
}

// Byte to index table for O(1) lookups when unmarshaling.
// We use -1 (all bits are set to 1) as sentinel value for invalid indexes.
// The reason for using -1 is that, even when cast, it does not lose the property that all bits are set to 1.
// e.g. uint64(int8(-1)) == 0xFFFFFFFFFFFFFFFF
//
// Reference: https://github.com/oklog/ulid/pull/116
// Original: @shogo82148
var dec = [...]int8{
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, 0x00, 0x01,
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, -1, -1,
	-1, -1, -1, -1, -1, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
	0x0F, 0x10, 0x11, -1, 0x12, 0x13, -1, 0x14, 0x15, -1,
	0x16, 0x17, 0x18, 0x19, 0x1A, -1, 0x1B, 0x1C, 0x1D, 0x1E,
	0x1F, -1, -1, -1, -1, -1, -1, 0x0A, 0x0B, 0x0C,
	0x0D, 0x0E, 0x0F, 0x10, 0x11, -1, 0x12, 0x13, -1, 0x14,
	0x15, -1, 0x16, 0x17, 0x18, 0x19, 0x1A, -1, 0x1B, 0x1C,
	0x1D, 0x1E, 0x1F, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1,
}

// EncodedSize is the length of a text encoded SULID.
const EncodedSize = 20

// UnmarshalText implements the encoding.TextUnmarshaler interface by
// parsing the data as string encoded SULID.
//
// ErrDataSize is returned if the len(v) is different from an encoded
// SULID's length. Invalid encodings produce undefined SULIDs.
func (id *SULID) UnmarshalText(v []byte) error {
	return parse(v, false, id)
}

// Time returns the Unix time in milliseconds encoded in the SULID.
// Use the top level Time function to convert the returned value to
// a time.Time.
func (id SULID) Time() uint64 {
	return uint64(id[5]) | uint64(id[4])<<8 |
		uint64(id[3])<<16 | uint64(id[2])<<24 |
		uint64(id[1])<<32 | uint64(id[0])<<40
}

// Timestamp returns the time encoded in the SULID as a time.Time.
func (id SULID) Timestamp() time.Time {
	return Time(id.Time())
}

// IsZero returns true if the SULID is a zero-value SULID, i.e. sulid.Zero.
func (id SULID) IsZero() bool {
	return id.Compare(Zero) == 0
}

// maxTime is the maximum Unix time in milliseconds that can be
// represented in a SULID.
var maxTime = SULID{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}.Time()

// MaxTime returns the maximum Unix time in milliseconds that
// can be encoded in a SULID.
func MaxTime() uint64 { return maxTime }

// Now is a convenience function that returns the current
// UTC time in Unix milliseconds. Equivalent to:
//
//	Timestamp(time.Now().UTC())
func Now() uint64 { return Timestamp(time.Now().UTC()) }

// Timestamp converts a time.Time to Unix milliseconds.
//
// Because of the way SULID stores time, times from the year
// 10889 produces undefined results.
func Timestamp(t time.Time) uint64 {
	return uint64(t.Unix())*1000 +
		uint64(t.Nanosecond()/int(time.Millisecond))
}

// Time converts Unix milliseconds in the format
// returned by the Timestamp function to a time.Time.
func Time(ms uint64) time.Time {
	s := int64(ms / 1e3)
	ns := int64((ms % 1e3) * 1e6)
	return time.Unix(s, ns)
}

// SetTime sets the time component of the SULID to the given Unix time
// in milliseconds.
func (id *SULID) SetTime(ms uint64) error {
	if ms > maxTime {
		return ErrBigTime
	}

	(*id)[0] = byte(ms >> 40)
	(*id)[1] = byte(ms >> 32)
	(*id)[2] = byte(ms >> 24)
	(*id)[3] = byte(ms >> 16)
	(*id)[4] = byte(ms >> 8)
	(*id)[5] = byte(ms)

	return nil
}

// Entropy returns the entropy from the SULID.
func (id SULID) Entropy() []byte {
	e := make([]byte, 6)
	copy(e, id[6:])
	return e
}

// SetEntropy sets the SULID entropy to the passed byte slice.
// ErrDataSize is returned if len(e) != 6.
func (id *SULID) SetEntropy(e []byte) error {
	if len(e) != 6 {
		return ErrDataSize
	}

	copy((*id)[6:], e)
	return nil
}

// Compare returns an integer comparing id and other lexicographically.
// The result will be 0 if id==other, -1 if id < other, and +1 if id > other.
func (id SULID) Compare(other SULID) int {
	return bytes.Compare(id[:], other[:])
}

// Scan implements the sql.Scanner interface. It supports scanning
// a string or byte slice.
func (id *SULID) Scan(src interface{}) error {
	switch x := src.(type) {
	case nil:
		return nil
	case string:
		return id.UnmarshalText([]byte(x))
	case []byte:
		return id.UnmarshalBinary(x)
	}

	return ErrScanValue
}

// Value implements the sql/driver.Valuer interface, returning the SULID as a
// slice of bytes, by invoking MarshalBinary. If your use case requires a string
// representation instead, you can create a wrapper type that calls String()
// instead.
//
//	type stringValuer sulid.SULID
//
//	func (v stringValuer) Value() (driver.Value, error) {
//	    return sulid.SULID(v).String(), nil
//	}
//
//	// Example usage.
//	db.Exec("...", stringValuer(id))
//
// All valid SULIDs, including zero-value SULIDs, return a valid Value with a nil
// error. If your use case requires zero-value SULIDs to return a non-nil error,
// you can create a wrapper type that special-cases this behavior.
//
//	var zeroValueSULID sulid.SULID
//
//	type invalidZeroValuer sulid.SULID
//
//	func (v invalidZeroValuer) Value() (driver.Value, error) {
//	    if sulid.SULID(v).Compare(zeroValueSULID) == 0 {
//	        return nil, fmt.Errorf("zero value")
//	    }
//	    return sulid.SULID(v).Value()
//	}
//
//	// Example usage.
//	db.Exec("...", invalidZeroValuer(id))
func (id SULID) Value() (driver.Value, error) {
	return id.MarshalBinary()
}

// Monotonic returns a source of entropy that yields strictly increasing entropy
// bytes, to a limit governeed by the `inc` parameter.
//
// Specifically, calls to MonotonicRead within the same SULID timestamp return
// entropy incremented by a random number between 1 and `inc` inclusive. If an
// increment results in entropy that would overflow available space,
// MonotonicRead returns ErrMonotonicOverflow.
//
// Passing `inc == 0` results in the reasonable default `math.MaxUint16`. Lower
// values of `inc` provide more monotonic entropy in a single millisecond, at
// the cost of easier "guessability" of generated SULIDs. If your code depends on
// SULIDs having secure entropy bytes, then it's recommended to use the secure
// default value of `inc == 0`, unless you know what you're doing.
//
// The provided entropy source must actually yield random bytes. Otherwise,
// monotonic reads are not guaranteed to terminate, since there isn't enough
// randomness to compute an increment number.
//
// The returned type isn't safe for concurrent use.
func Monotonic(entropy io.Reader, inc uint32) *MonotonicEntropy {
	m := MonotonicEntropy{
		Reader: bufio.NewReader(entropy),
		inc:    inc,
	}

	if m.inc == 0 {
		m.inc = math.MaxUint16
	}

	return &m
}

// LockedMonotonicReader wraps a MonotonicReader with a sync.Mutex for safe
// concurrent use.
type LockedMonotonicReader struct {
	mu sync.Mutex
	MonotonicReader
}

// MonotonicRead synchronizes calls to the wrapped MonotonicReader.
func (r *LockedMonotonicReader) MonotonicRead(ms uint64, p []byte) (err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.MonotonicReader.MonotonicRead(ms, p)
}

// MonotonicEntropy is an opaque type that provides monotonic entropy.
type MonotonicEntropy struct {
	io.Reader
	ms      uint64
	inc     uint32
	entropy uint48
	rand    [4]byte
}

// MonotonicRead implements the MonotonicReader interface.
func (m *MonotonicEntropy) MonotonicRead(ms uint64, entropy []byte) (err error) {
	if !m.entropy.IsZero() && m.ms == ms {
		err = m.increment()
		m.entropy.AppendTo(entropy)
	} else if _, err = io.ReadFull(m.Reader, entropy); err == nil {
		m.ms = ms
		m.entropy.SetBytes(entropy)
	}
	return err
}

// increment the previous entropy number with a random number
// of up to m.inc (inclusive).
func (m *MonotonicEntropy) increment() error {
	inc, err := m.random()
	if err != nil {
		return err
	}

	overflowed := m.entropy.Add(inc)
	if overflowed {
		return ErrMonotonicOverflow
	}

	return nil
}

// random returns a uniform random value in [1, m.inc), reading entropy
// from m.Reader. When m.inc == 0 || m.inc == 1, it returns 1.
// Adapted from: https://golang.org/pkg/crypto/rand/#Int
func (m *MonotonicEntropy) random() (inc uint32, err error) {
	if m.inc <= 1 {
		return 1, nil
	}

	// bitLen is the maximum bit length needed to encode a value < m.inc.
	bitLen := bits.Len32(m.inc)

	// byteLen is the maximum byte length needed to encode a value < m.inc.
	byteLen := uint(bitLen+7) / 8

	// msbitLen is the number of bits in the most significant byte of m.inc-1.
	msbitLen := uint(bitLen % 8)
	if msbitLen == 0 {
		msbitLen = 8
	}

	for inc == 0 || inc >= m.inc {
		if _, err = io.ReadFull(m.Reader, m.rand[:byteLen]); err != nil {
			return 0, err
		}

		// Clear bits in the first byte to increase the probability
		// that the candidate is < m.inc.
		m.rand[0] &= uint8(int(1<<msbitLen) - 1)

		// Convert the read bytes into an uint64 with byteLen
		// Optimized unrolled loop.
		switch byteLen {
		case 1:
			inc = uint32(m.rand[0])
		case 2:
			inc = uint32(binary.LittleEndian.Uint16(m.rand[:2]))
		case 3, 4:
			inc = uint32(binary.LittleEndian.Uint32(m.rand[:4]))
		}
	}

	// Range: [1, m.inc)
	return 1 + inc, nil
}

type uint48 struct {
	Hi uint16
	Lo uint32
}

func (u *uint48) SetBytes(bs []byte) {
	u.Hi = binary.BigEndian.Uint16(bs[:2])
	u.Lo = binary.BigEndian.Uint32(bs[2:])
}

func (u *uint48) AppendTo(bs []byte) {
	binary.BigEndian.PutUint16(bs[:2], u.Hi)
	binary.BigEndian.PutUint32(bs[2:], u.Lo)
}

func (u *uint48) Add(n uint32) (overflow bool) {
	lo, hi := u.Lo, u.Hi
	if u.Lo += n; u.Lo < lo {
		u.Hi++
	}
	return u.Hi < hi
}

func (u uint48) IsZero() bool {
	return u.Hi == 0 && u.Lo == 0
}
