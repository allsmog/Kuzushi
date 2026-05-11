# 01 — PROXY-protocol v1 one-byte stack OOB write

- **Status**: VERIFIED
- **Severity**: medium (DoS via stack-canary abort) / high (worst-case stack corruption)
- **File**: `sql/proxy_protocol.cc`
- **Line(s)**: 175–211 (declare 177; bug 207)
- **CWE**: CWE-787 (Out-of-bounds Write), CWE-193 (Off-by-one)
- **Discovered by**: `carlini-threat-hunt:run`, fingerprint `ea5911ba9c606f49`
- **Disclosure**: filed at `/home/user/mariadb-disclosures/1-proxy-v1-oob-write.txt`

## Summary

`parse_proxy_protocol_header()` reads bytes one at a time into a 256-byte
`uchar hdr[]` while `pos < sizeof(hdr)`. After 252 attacker bytes with no
`\n`, `pos == 256` and the post-loop `hdr[pos] = 0;` writes one byte past
the end of the stack buffer. Reachable from any TCP client whose source
matches `proxy_protocol_networks`.

## Source quote

```c
// proxy_protocol.cc
30:  #define MAX_PROXY_HEADER_LEN 256
177:   uchar hdr[MAX_PROXY_HEADER_LEN];        // valid hdr[0..255]
191:   pos= NET_HEADER_SIZE;                   // pos = 4
198:   while(pos < sizeof(hdr)) {              // pos < 256
200:     long len= (long)vio_read(vio, hdr + pos, 1);
201:     if (len < 0) return -1;
202:     pos++;
203:     if (hdr[pos-1] == '\n') break;
204:   }
207:   hdr[pos]= 0;                            // OOB when pos == 256
```

## Verification notes

Read end-to-end. `MAX_PROXY_HEADER_LEN = 256` (line 30, mysql_com.h).
`NET_HEADER_SIZE = 4` (mysql_com.h:706). Trace from pos=4 to pos=256 holds.
Caller chain via `sql/net_serv.cc:783` → `parse_proxy_protocol_header(net,
&peer_info)` confirms pre-auth reachability during COM_CONNECT.

## Suggested fix

Bound the loop at `sizeof(hdr) - 1` and reject headers that don't terminate
within budget; see disclosure doc for diff.
