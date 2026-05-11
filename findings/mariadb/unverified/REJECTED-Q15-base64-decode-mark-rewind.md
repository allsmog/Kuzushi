# REJECTED — Q15: `my_base64_decode` mark-count rewind cannot underflow `d`

- **Status**: REJECTED (false positive — model classified as CWE-193
  off-by-one; the mark-count rewind is bounded by the structure of
  the decoder state machine and cannot underflow)
- **File originally cited**: `mysys/base64.c`
- **Title from agent artifact**: "my_base64_decode trusts mark count
  without bounding output rewind on malformed padding sequence"
  (`.kuzushi/systems-hunt/fe64bbe0749efd48.json`)
- **Discovered by**: `systems-hunt:systems-hunt` (default budget; queue Q15)

## Why this is rejected

The decoder loop in `my_base64_decode` (lines 326-348):

```c
// mysys/base64.c
326: for ( ; ; )
327: {
328:   decoder.c= 0;
329:   decoder.state= 0;
330:
331:   if (my_base64_decoder_getch(&decoder) ||
332:       my_base64_decoder_getch(&decoder) ||
333:       my_base64_decoder_getch(&decoder) ||
334:       my_base64_decoder_getch(&decoder))
335:     break;
336:
337:   *d++= (decoder.c >> 16) & 0xff;        // +1
338:   *d++= (decoder.c >>  8) & 0xff;        // +1
339:   *d++= (decoder.c >>  0) & 0xff;        // +1, total +3
340:
341:   if (decoder.mark)
342:   {
343:     d-= decoder.mark;                    // -mark
344:     if (!(flags & MY_BASE64_DECODE_ALLOW_MULTIPLE_CHUNKS))
345:       break;
346:     decoder.mark= 0;                     // reset
347:   }
348: }
```

For the rewind at line 343 to underflow `d` below the original `dst`,
`decoder.mark` must exceed the cumulative `+3` advance from lines
337-339. But:

1. **`decoder.mark` is bounded to ≤ 2 in a single 4-char group.** The
   only place `mark++` happens is inside `my_base64_decoder_getch` at
   line 272, gated on `case 2: case 3:` (state machine — only the 3rd
   and 4th positions in a group accept a `=` pad). So in any single
   group iteration, `mark ≤ 2`.

2. **`mark` is reset between iterations.** Line 346 sets `mark = 0`
   when the loop continues (`MY_BASE64_DECODE_ALLOW_MULTIPLE_CHUNKS`
   set). When the flag is not set, the loop breaks at line 345 — no
   second iteration happens.

3. **The pre-rewind advance is `+3`.** Lines 337-339 unconditionally
   advance `d` by 3 before the rewind check.

So per iteration: net advance = `3 - mark`, which is in `{1, 2, 3}`
— always positive. `d` cannot underflow `dst`.

A possible alternative reading is "the mark might be carried across
iterations and silently corrupt subsequent chunks" — but that fails
on the `decoder.mark = 0` reset at line 346.

**Conclusion:** No off-by-one or rewind underflow. The decoder is
robust under the malformed inputs the agent's hypothesis describes.

## Note for future audits

Patterns to watch:

- If `mark` ever became `int` and could go negative (e.g. via a
  refactor that decrements it), the bound would no longer hold.
- If a future patch adds another `mark++` site in the state machine
  outside `case 2: case 3:`, mark could exceed 2.
- The `*d++ = ...` triple is *speculatively* run even when the data
  is later truncated by `mark`. If a caller sized the buffer
  exactly to `my_base64_needed_decoded_length()` and the input was
  malformed in a way that produced large `mark` (which can't happen
  per the analysis above), a write to `dst[N+1]` could matter. This
  is purely theoretical given the current state machine.
