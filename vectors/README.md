# Shared client-builder vectors

- `inputs.json`: fixed throwaway test keys and claims. Each port's emitter builds a credential from them into
  `out/<lang>.json` (git-ignored), and `../verify-interop.sh` runs every one through the Java AS-side
  verifier.
- `htu.json`: request URLs and the DPoP `htu` and nonce origin every port must produce for them, or the
  error message every port must refuse them with. Each port's test suite runs every case through its
  `DpopProofBuilder` and its DPoP nonce key.
- `spire-cli.json`: fake `spire-agent` shell scripts that start a helper holding stdout open, and the token
  or exact error every port's SPIRE CLI source must give for each, within a time limit. The rule: the
  agent's exit decides, so once it has exited stdout is read for at most 250 ms more and then closed; on
  exit status 0 what was read is parsed (the first token wins), and any other status or a kill fails the
  fetch.

## The `htu` rule

RFC 9449 section 4.2 makes `htu` the request's target URI without query and fragment. RFC 3986 section 6
lets a server compare it after syntax-based normalisation, but the four languages' URL parsers normalise
differently (WHATWG resolves dot-segments, compresses IPv6 and converts IDN hosts; `java.net.URI` finds no
host in a name with `_`). So each port reads the URL string itself, the same way:

1. Refuse a backslash, ASCII whitespace or a control character before the first `?` or `#`, then drop
   everything from that character on.
2. The scheme is the text before the first `://`, lower-cased. It must be `http` or `https`; anything else
   (a relative URL, another scheme, `https:/x`) is refused.
3. The authority runs to the next `/`; the path is the rest (possibly empty). Userinfo, everything up to
   the last `@` in the authority, is dropped.
4. A host in `[...]` is an IP literal: only hex digits, `:` and `.`, at least one `:`, kept as written but
   lower-cased (not compressed). Anything after `]` other than `:port` is refused, as is a zone or
   IPvFuture literal.
5. Any other host runs to the first `:` and must be non-empty RFC 3986 unreserved characters (ASCII
   letters, digits, `-`, `.`, `_`, `~`). It is lower-cased. A non-ASCII (IDN) host is refused: the
   languages' IDNA implementations disagree, so give the A-label (`xn--...`) form.
6. A port must be ASCII digits with a value of at most 65535. It is written as a plain decimal number and
   dropped when it is the scheme's default (80, 443). An empty port is dropped.
7. The path is kept as written: dot-segments are not resolved, `%XX` escapes are not decoded or re-cased,
   and every ASCII character stays as it is, including ones outside RFC 3986 `pchar` (`[ ] | ^ { } " < >`
   and `` ` ``) and a `%` that does not start a `%XX` escape (`/100%`). Only a non-ASCII character is
   percent-encoded, as UTF-8 with upper-case hex (`é` becomes `%C3%A9`). An empty path stays empty:
   `https://as.example.com` has no trailing `/`. A path that is not valid Unicode (a lone surrogate) is
   refused.

   This is so `htu` is the request target the HTTP client actually sends. Each SDK integration (Go
   `RoundTripper`, TypeScript `fetch`, Python `requests_auth` and `httpx_auth`, Java `send`) builds the
   proof from the URL it puts on the wire, and clients differ on which ASCII characters they escape (Go
   and WHATWG `fetch` send `[` and `]` as written; `requests` escapes them). RFC 9449 section 4.3 lets
   the server compare after RFC 3986 section 6.2.2 normalisation, which decodes only unreserved
   characters, so `/items%5B0%5D` does not match a request for `/items[0]`.

`htu` is `scheme://host[:port]` followed by the path. The DPoP nonce memory keys a URL on
`scheme://host[:port]` from the same rule; a URL the rule refuses is its own key.
