# Shorter ULID

A fork from [oklog/ulid](https://github.com/oklog/ulid), but shorter.

## Differences

1. The random field of the **ULID** is 80 bits.  
   The random field of the **SULID** is 48 bits.  

   I cut the last 32 bits of the random field, which will save 6 bytes of memory space. (The length of the ULID is 26 and the length of the SULID is 20.)  
   I think that a collision probability of 1/(2^48) per millisecond can still cover most scenarios. 

2. Default random number generation of **ULID** uses `math/rand`.   
   Default random number generation of **SULID** uses `math/rand/v2`. 

   Generating stronger random sequences using the `Chacha8` algorithm from `math/rand/v2` with tiny performance loss.   

   > Overall, ChaCha8Rand is slower than the Go 1 generator, but it is never more than twice as slow, and on typical servers the difference is never more than 3ns. Very few programs will be bottlenecked by this difference, and many programs will enjoy the improved security.
   >
   > *[Secure Randomness in Go 1.22](https://go.dev/blog/chacha8rand)*

### Binary Layout and Byte Order of **ULID**

The components are encoded as 16 octets. Each component is encoded with the Most Significant Byte first (network byte order).

```
        0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      32_bit_uint_time_high                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     16_bit_uint_time_low      |       16_bit_uint_random      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       32_bit_uint_random                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       32_bit_uint_random                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Binary Layout and Byte Order of **SULID**

The components are encoded as 12 octets. Each component is encoded with the Most Significant Byte first (network byte order).

```
        0               1               2               3
 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      32_bit_uint_time_high                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     16_bit_uint_time_low      |       16_bit_uint_random      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       32_bit_uint_random                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Install

This package requires Go modules.

```shell
go get -u github.com/cyberxnomad/sulid
```

## Specification

Below is the current specification of SULID as implemented in this repository.

### Components

**Timestamp**
- 48 bits
- UNIX-time in milliseconds
- Won't run out of space till the year 10889 AD

**Entropy**
- 48 bits
- User defined entropy source
- Monotonicity within the same millisecond with sulid.Monotonic

### Encoding

[Crockford's Base32](http://www.crockford.com/wrmg/base32.html) is used as shown.
This alphabet excludes the letters I, L, O, and U to avoid confusion and abuse.

```
0123456789ABCDEFGHJKMNPQRSTVWXYZ
```

### String Representation

```
 0000XSNJG0      55WMAVS5Z8
|----------|    |----------|
 Timestamp        Entropy
  10 chars        10 chars
   48bits          48bits
   base32          base32
```

## Test

```shell
go test ./...
```