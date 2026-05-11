# 02 — PROXY-protocol v2 trailer-length inverted shift → uninit-stack disclosure

- **Status**: VERIFIED
- **Severity**: medium / high (pre-auth ASLR-relevant info leak)
- **File**: `sql/proxy_protocol.cc`
- **Line(s)**: 220 (decode); 131-140 (sink in `parse_v2_header`)
- **CWE**: CWE-908 (Use of Uninitialized Resource), CWE-457, CWE-200 (info exposure); secondary CWE-444 (smuggling/desync)
- **Discovered by**: `carlini-threat-hunt:run`, fingerprint `cf6388de0145f2d7`
- **Disclosure**: filed at `/home/user/mariadb-disclosures/2-proxy-v2-shift-uninit-disclosure.txt`

## Summary

The big-endian decode of the v2 trailer-length field uses `>>` instead of
`<<`. `(ushort)hdr[14] >> 8` is always 0 since `hdr[14]` is `uchar`, so
`trail_len` collapses to just `hdr[15]` — capped at 255 regardless of
what the wire said. With a 16-byte v2 header containing
`fam=0x21, hdr[14]=0, hdr[15]=0`, the extra-trailer read at line 223 is
skipped, and `parse_v2_header()` then copies `hdr[16..31]` into
`peer_addr` and `hdr[48..49]` into `port` — both **uninitialised stack**.
That's 18 bytes of stack residue per connection, recorded onto the THD
via `thd_set_peer_addr()` and observable post-auth through `SHOW
PROCESSLIST` / `USER()` / `INFORMATION_SCHEMA.PROCESSLIST` / audit log.

## Source quote

```c
// proxy_protocol.cc
220: ushort trail_len= ((ushort)hdr[PROXY_V2_HEADER_LEN-2] >> 8) + hdr[PROXY_V2_HEADER_LEN-1];
                                                              ^^ should be <<

// parse_v2_header() — copies into peer_info regardless of len
136: case 0x21:  /* TCPv6 */
138:   memcpy(&(sin6->sin6_addr), hdr + 16, 16);   // OOB into uninit hdr[16..31]
139:   peer_info->port= (hdr[48] << 8) + hdr[49];  // ditto hdr[48..49]
```

## Verification notes

Read in source. `parse_v2_header()` does not check `len` against
expected per-family trailer size (12 for TCPv4, 36 for TCPv6) before
copying. Caller chain via `net_serv.cc:783, 796` confirms `peer_addr` and
`port` flow into `thd_set_peer_addr`. `SHOW PROCESSLIST` exposure is the
documented behaviour.

Smuggling angle: when `hdr[14]` is non-zero (intended trail_len ≥ 256),
the buggy decode reads fewer bytes than were sent on the wire; leftovers
are consumed as the next MySQL packet by a pipelining proxy. Real but
harder to weaponise; foregrounded the disclosure path in the report.

## Suggested fix

One-character: `>>` → `<<`. Plus per-family `len` check in
`parse_v2_header()` and `uchar hdr[MAX_PROXY_HEADER_LEN] = {};`
zero-init for defence in depth. See disclosure doc.
