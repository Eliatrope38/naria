package submission

import (
	_ "embed"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// tldList is the IANA list of top-level domains
// (https://data.iana.org/TLD/tlds-alpha-by-domain.txt). Mail clients only make a
// bare name clickable when it ends with one: "cv.pdf" is a file, "photo.zip" a link.
//
//go:embed tlds-alpha-by-domain.txt
var tldList string

var tlds = func() map[string]bool {
	m := map[string]bool{}
	for _, line := range strings.Split(tldList, "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			m[strings.ToLower(line)] = true
		}
	}
	return m
}()

// maxSchemeLen bounds the backward look for a scheme before ":", so that scanning
// stays linear on a long run of letters.
const maxSchemeLen = 32

// maxHostLen is the longest DNS name. A longer host yields no blocklist key.
const maxHostLen = 253

// maxSuffixLabels bounds the parent domains a host yields as keys, so that a
// single deep host ("a.a.a...example") cannot use up the budget of a submission.
// A blocked domain of more labels only matches that exact host.
const maxSuffixLabels = 6

// A link is a span of free text that a browser, a mail client or a chat service
// may open.
type link struct {
	start, end int
	// schemeEnd is the offset of ":" after the scheme, or start when there is none.
	schemeEnd int
	// authStart begins the authority (userinfo then host); hostEnd ends the host.
	authStart, hostEnd int
	// host is normalized as a browser would resolve it; empty for a bracketed
	// IPv6 literal, a file URL without a host, or a host made only of characters
	// a browser drops.
	host string
	// strict links are written as links: a scheme, "www." or a host followed by a
	// path. The others are bare domain names, which mail clients often turn into
	// links too, but which also match "ASP.NET" or "README.md".
	strict bool
}

// compat returns the compatibility decomposition of a rune, nil if it has none.
// Browsers map a host through it (UTS 46): "ⓢ" opens as "s", "․" as ".".
func compat(r rune) []byte {
	var buf [utf8.UTFMax]byte
	return norm.NFKC.Properties(utf8.AppendRune(buf[:0], r)).Decomposition()
}

func isDotRune(r rune) bool {
	// The ideographic full stops have no decomposition, but browsers read them as dots.
	return r == '.' || r == '\u3002' || r == '\uff61' || r >= utf8.RuneSelf && string(compat(r)) == "."
}

// isHostRune also admits invisible characters and combining marks: normalizeHost
// drops them, so a name cannot hide behind them.
func isHostRune(r rune) bool {
	if r == '-' || r == '_' || r == '%' || isDotRune(r) ||
		unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.M, r) || unicode.Is(unicode.Cf, r) {
		return true
	}
	if r < utf8.RuneSelf {
		return false
	}
	d := compat(r)
	for _, c := range d {
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '-' && c != '.' {
			return false
		}
	}
	return len(d) > 0
}

func isSchemeByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'
}

func isASCIILetter(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// specialSchemes are those a browser opens without "//" ("https:evil.example").
var specialSchemes = map[string]bool{"http": true, "https": true, "ftp": true, "ws": true, "wss": true, "file": true}

// authorityEnd reports whether a character ends a URL authority, for a browser
// (/ \ ? #) or for the autolinkers of mail clients (space, quotes, angle brackets).
func authorityEnd(r rune) bool {
	return r == '/' || r == '\\' || r == '?' || r == '#' || r == '"' || r == '<' || r == '>' || unicode.IsSpace(r)
}

// authorityCache remembers the end of the last authority read, its last "@" and
// the host after it. Links are found left to right, so a run without any
// terminator is read once however many schemes it holds, and so is a host that
// every scheme before the same "@" points to.
type authorityCache struct {
	start, end, lastAt int
	valid              bool

	hostAt, hostEnd int
	host            string
}

func (c *authorityCache) read(s string, p int) (end, lastAt int) {
	if !c.valid || p < c.start || p >= c.end {
		c.start, c.end, c.lastAt, c.valid, c.hostAt = p, len(s), -1, true, -1
		for i, r := range s[p:] {
			if authorityEnd(r) {
				c.end = p + i
				break
			}
			if r == '@' {
				c.lastAt = p + i
			}
		}
	}
	if c.lastAt < p {
		return c.end, -1
	}
	return c.end, c.lastAt
}

// readHost reads the host that starts at h, within an authority ending at end. An
// IPv6 literal, or an unclosed bracket, has no host to compare.
func (c *authorityCache) readHost(s string, h, end int) (hostEnd int, host string) {
	if c.hostAt != h {
		c.hostAt, c.hostEnd, c.host = h, h, ""
		switch {
		case h < end && s[h] == '[':
			if bracket := strings.IndexByte(s[h:end], ']'); bracket >= 0 {
				c.hostEnd = h + bracket + 1
			}
		default:
			c.hostEnd = trimDots(s, h, hostRunEnd(s, h))
			c.host = normalizeHost(s[h:c.hostEnd])
		}
	}
	return c.hostEnd, c.host
}

// scanLinks finds the links of a text, left to right and without overlap. It
// reads each byte a bounded number of times: the text comes from an anonymous
// visitor.
func scanLinks(s string) []link {
	var out []link
	var auth authorityCache
	lo := 0 // a scheme never starts inside a previous link
	prev := rune(-1)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		var l link
		found := false
		switch {
		case r == ':':
			l, found = schemeLink(s, i, lo, &auth)
		case r == '\\' && strings.HasPrefix(s[i:], `\\`) && !isHostRune(prev):
			l, found = uncLink(s, i)
		case isHostRune(r) && !isHostRune(prev):
			j := hostRunEnd(s, i)
			if !afterAddressAt(s, i) {
				l, found = bareLink(s, i, j)
				if !found && j < len(s) && s[j] == ':' {
					// "evil.example.http://x": the scheme takes the last label, the
					// name before it is a link of its own.
					if k := lastDot(s[i:j]); k > 0 {
						l, found = bareLink(s, i, i+k)
					}
				}
			}
			if !found {
				// The run holds no link; a scheme ending it is read at the ":".
				prev, _ = utf8.DecodeLastRuneInString(s[:j])
				i = j
				continue
			}
		}
		if found {
			out = append(out, l)
			i, lo = l.end, l.end
			prev, _ = utf8.DecodeLastRuneInString(s[:i])
			continue
		}
		prev = r
		i += size
	}
	return out
}

// afterAddressAt reports whether the run at i is the domain of an e-mail address:
// it follows an "@" and a non-empty local part that is not itself part of a URL,
// as in "x:/@evil.example" or "/u@evil.example".
func afterAddressAt(s string, i int) bool {
	if i < 2 || s[i-1] != '@' {
		return false
	}
	const maxLocalPart = 64
	k := i - 1
	for k > 0 && i-1-k <= maxLocalPart {
		r, size := utf8.DecodeLastRuneInString(s[:k])
		if unicode.IsSpace(r) || strings.ContainsRune(`/\:@<>()[]",;`, r) {
			return k < i-1 && r != '/' && r != '\\' && r != '@'
		}
		k -= size
	}
	return k == 0 && i-1 > 0
}

// lastDot returns the offset of the last dot of s, 0 if there is none.
func lastDot(s string) int {
	for k := len(s); k > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:k])
		k -= size
		if isDotRune(r) {
			return k
		}
	}
	return 0
}

func hostRunEnd(s string, i int) int {
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if !isHostRune(r) {
			break
		}
		i += size
	}
	return i
}

// trimDots drops the dots that end a host, usually the end of a sentence.
func trimDots(s string, start, end int) int {
	for end > start {
		r, size := utf8.DecodeLastRuneInString(s[start:end])
		if !isDotRune(r) {
			break
		}
		end -= size
	}
	return end
}

// portEnd skips a ":port" after a host.
func portEnd(s string, i int) int {
	if i >= len(s) || s[i] != ':' {
		return i
	}
	j := i + 1
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		j++
	}
	if j == i+1 {
		return i
	}
	// "x:8.evil.example" is a host after a colon, not a port.
	if r, _ := utf8.DecodeRuneInString(s[j:]); j < len(s) && isHostRune(r) {
		return i
	}
	return j
}

// schemeLink reads a link whose ":" is at c. The scheme need not start a word:
// some clients link the "https://..." part of "xhttps://...".
func schemeLink(s string, c, lo int, auth *authorityCache) (link, bool) {
	start := c
	for start > lo && c-start < maxSchemeLen && isSchemeByte(s[start-1]) {
		start--
	}
	for start < c && !isASCIILetter(s[start]) {
		start++
	}
	// One letter is a drive ("C:\Users"), not a scheme.
	if c-start < 2 {
		return link{}, false
	}
	scheme := strings.ToLower(s[start:c])
	p, slashes := c+1, 0
	// Browsers skip any number of slashes and backslashes after a special scheme.
	for p < len(s) && (s[p] == '/' || s[p] == '\\') {
		p++
		slashes++
	}
	if slashes == 0 && !specialSchemes[scheme] {
		return link{}, false
	}
	end, lastAt := auth.read(s, p)
	hostStart := p
	if lastAt >= 0 {
		hostStart = lastAt + 1
	}
	hostEnd, host := auth.readHost(s, hostStart, end)
	hostEnd, host = yieldScheme(s, hostStart, hostEnd, host)
	switch {
	// A file URL without a host still opens a local path. Any other link needs an
	// authority, even one whose host a browser would reject.
	case end == p && (scheme != "file" || slashes == 0):
		return link{}, false
	// Without "//", "File:report" is a word: only a dotted name makes it a link.
	case slashes == 0 && !strings.Contains(host, "."):
		return link{}, false
	}
	return link{
		start: start, end: portEnd(s, hostEnd), schemeEnd: c, authStart: p, hostEnd: hostEnd, host: host, strict: true,
	}, true
}

// schemeAt reports whether a scheme ends at i: a ":" then a slash or a backslash.
func schemeAt(s string, i int) bool {
	return i+1 < len(s) && s[i] == ':' && (s[i+1] == '/' || s[i+1] == '\\')
}

// yieldScheme leaves the last label of a host followed by ":/" to the scheme it
// starts, as in "a0:/x.http://y". The host keeps its whole name for the
// blocklist, and its last dot stays in the link, so that it is defanged too.
func yieldScheme(s string, hostStart, hostEnd int, host string) (int, string) {
	if !schemeAt(s, hostEnd) {
		return hostEnd, host
	}
	k := strings.LastIndexFunc(s[hostStart:hostEnd], isDotRune)
	if k < 0 {
		return hostStart, ""
	}
	_, size := utf8.DecodeRuneInString(s[hostStart+k:])
	return hostStart + k + size, host
}

// uncLink reads a Windows network path (\\host\share), which Outlook opens.
func uncLink(s string, i int) (link, bool) {
	hostEnd := trimDots(s, i+2, hostRunEnd(s, i+2))
	hostEnd, host := yieldScheme(s, i+2, hostEnd, normalizeHost(s[i+2:hostEnd]))
	if host == "" {
		return link{}, false
	}
	return link{start: i, end: hostEnd, schemeEnd: i, authStart: i + 2, hostEnd: hostEnd, host: host, strict: true}, true
}

// bareLink reads a link without a scheme in the run of host characters [i, j):
// "www.example.com", "example.com/page" or "example.com".
func bareLink(s string, i, j int) (link, bool) {
	hostEnd := trimDots(s, i, j)
	if hostEnd == j && j < len(s) && s[j] == '@' {
		return link{}, false // the local part of an address
	}
	host := normalizeHost(s[i:hostEnd])
	dot := strings.LastIndexByte(host, '.')
	if dot < 0 || !isTLD(host[dot+1:]) {
		return link{}, false
	}
	end := hostEnd
	path := false
	if hostEnd == j {
		end = portEnd(s, j)
		switch {
		case end < len(s) && s[end] == '/':
			path = true
		case end == j && schemeAt(s, j):
			// "evil.online:/x": a scheme read from the ":" would leave the
			// dotted host behind, unblocked and clickable.
			path = true
			end = hostEnd
		default:
			end = hostEnd
		}
	}
	return link{
		start: i, end: end, schemeEnd: i, authStart: i, hostEnd: hostEnd, host: host,
		strict: path || strings.HasPrefix(host, "www."),
	}, true
}

// isTLD reports whether a label is a top-level domain. A label of at least two
// non-ASCII letters is taken as one: without an IDN library, its ASCII form
// cannot be looked up.
func isTLD(label string) bool {
	if tlds[label] {
		return true
	}
	n := 0
	for _, r := range label {
		if r < utf8.RuneSelf || !unicode.IsLetter(r) {
			return false
		}
		n++
	}
	return n >= 2
}

// normalizeHost reads a host as a browser resolves it: percent-decoded, in NFKC
// (fullwidth letters become ASCII), lowercase, without invisible characters or
// combining marks, with every kind of dot as ".". A real IDN stays in Unicode: the
// blocklist only holds ASCII, so only its ASCII parent domains can match.
func normalizeHost(h string) string {
	if strings.Contains(h, "%") {
		if u, err := url.PathUnescape(h); err == nil {
			h = u
		}
	}
	h = norm.NFKC.String(h)
	h = strings.Map(func(r rune) rune {
		switch {
		case isDotRune(r):
			return '.'
		case unicode.Is(unicode.Cf, r), unicode.Is(unicode.Mn, r):
			return -1
		}
		return unicode.ToLower(r)
	}, h)
	return strings.Trim(h, ".")
}

// hostKeys adds the blocklist keys of a host: the host, its parent domains of at
// most maxSuffixLabels labels, then its extension (".online"). Only the ASCII
// labels on the right count, and a numeric address has none.
func hostKeys(host string, add func(string) bool) {
	if host == "" || len(host) > maxHostLen {
		return
	}
	labels := strings.Split(host, ".")
	first := len(labels)
	for first > 0 && asciiLabel(labels[first-1]) {
		first--
	}
	ascii := labels[first:]
	if len(ascii) == 0 || allDigits(ascii[len(ascii)-1]) {
		return
	}
	for k := 0; k < len(ascii)-1; k++ {
		if k > 0 && len(ascii)-k > maxSuffixLabels {
			continue
		}
		if !add(strings.Join(ascii[k:], ".")) {
			return
		}
	}
	if tld := ascii[len(ascii)-1]; isTLD(tld) {
		add("." + tld)
	}
}

func asciiLabel(l string) bool {
	if l == "" {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

func allDigits(l string) bool {
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

// HasLink reports whether a name or a value holds a link written as one: with a
// scheme, "www." or a path. A bare domain name does not count, so as not to take
// "ASP.NET" for a link.
func HasLink(fields []Field) bool {
	for _, f := range fields {
		for _, text := range [2]string{f.Name, f.Value} {
			for _, l := range scanLinks(text) {
				if l.strict {
					return true
				}
			}
		}
	}
	return false
}

// SafeCut returns where to cut a text defanged as a whole, at or before i. A cut
// inside a dotted name can make it a link again that Defang did not see:
// "evil.onlinezz" cut after "online". It then moves to the start of that name.
func SafeCut(s string, i int) int {
	if i >= len(s) {
		return i
	}
	if r, _ := utf8.DecodeRuneInString(s[i:]); !isHostRune(r) {
		return i
	}
	j := i
	for j > 0 {
		r, size := utf8.DecodeLastRuneInString(s[:j])
		if !isHostRune(r) {
			break
		}
		j -= size
	}
	if strings.IndexFunc(s[j:i], isDotRune) >= 0 {
		return j
	}
	return i
}

// Defang rewrites the links of a text so that the usual mail clients and chat
// services do not make them clickable: "https://evil.example/x" becomes
// "hxxps://evil[.]example/x". Bare domain names are rewritten too, where a false
// positive only costs brackets.
func Defang(s string) string {
	links := scanLinks(s)
	if len(links) == 0 {
		return s
	}
	var b strings.Builder
	last := 0
	for _, l := range links {
		b.WriteString(s[last:l.start])
		if l.schemeEnd > l.start {
			scheme := s[l.start:l.schemeEnd]
			lower := strings.ToLower(scheme)
			switch {
			case strings.HasSuffix(lower, "https"):
				k := len(scheme) - len("https")
				b.WriteString(scheme[:k+1] + "xx" + scheme[k+3:] + ":")
			case strings.HasSuffix(lower, "http"):
				k := len(scheme) - len("http")
				b.WriteString(scheme[:k+1] + "xx" + scheme[k+3:] + ":")
			default:
				b.WriteString(scheme + "[:]")
			}
			b.WriteString(s[l.schemeEnd+1 : l.authStart])
		} else {
			b.WriteString(s[l.start:l.authStart])
		}
		auth := s[l.authStart:l.hostEnd]
		for k := 0; k < len(auth); {
			r, size := utf8.DecodeRuneInString(auth[k:])
			switch {
			case isDotRune(r):
				b.WriteString("[.]")
			case r == '%' && k+3 <= len(auth) && strings.EqualFold(auth[k:k+3], "%2e"):
				b.WriteString("[.]")
				size = 3
			// Any other escape may hide a dot too ("%E3%80%82").
			case r == '%':
				b.WriteString("[%]")
			// A single character may stand for a dot inside its expansion ("㏘" is "p.m.").
			case r >= utf8.RuneSelf && strings.Contains(string(compat(r)), "."):
				b.WriteString(strings.ReplaceAll(string(compat(r)), ".", "[.]"))
			default:
				b.WriteString(auth[k : k+size])
			}
			k += size
		}
		b.WriteString(s[l.hostEnd:l.end])
		last = l.end
	}
	b.WriteString(s[last:])
	return b.String()
}
