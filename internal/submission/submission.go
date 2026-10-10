// Package submission reads, bounds and serializes submissions received at the public entry point.
// Nothing from an anonymous visitor reaches the rest of the code without going through here.
package submission

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/mail"
	"net/url"
	"os"
	"strconv"
	"strings"
	"unicode"
)

// The form's field order is kept until display and email.
type Field struct {
	Name  string `json:"n"`
	Value string `json:"v"`
}

type File struct {
	Name string
	Data []byte
}

type Limits struct {
	MaxFields   int
	MaxNameLen  int // bytes
	MaxValueLen int // bytes
}

var DefaultLimits = Limits{MaxFields: 60, MaxNameLen: 100, MaxValueLen: 20000}

// A MaxFiles of zero ignores files.
type FileLimits struct {
	MaxFiles int
	MaxBytes int64 // cumulative size, bytes
}

// FileGate decides the fate of the files in a multipart submission, before a single byte is kept.
// Parse calls it at the first file, with the service fields read so far. Its error aborts the read.
type FileGate func(seen Meta) (FileLimits, error)

// In an email's Content-Disposition header, each byte can become three (RFC 2231):
// at 255, the line stays under the 998 bytes SMTP allows.
const maxFileNameLen = 255

var (
	ErrUnsupportedType = errors.New("type de contenu non pris en charge")
	ErrMalformed       = errors.New("corps de requête invalide")
	ErrTooManyFields   = errors.New("trop de champs")
	ErrFieldTooLong    = errors.New("champ trop long")
	ErrTooManyFiles    = errors.New("trop de fichiers")
	ErrFilesTooLarge   = errors.New("fichiers trop volumineux")
)

// Parse reads the fields of a submission, in the order sent. Formats: HTML form (urlencoded
// or multipart) and JSON. Without a gate, files are ignored. A kept file leaves its name
// as the value of its field. The body size cap is set upstream; exceeding it
// surfaces as *http.MaxBytesError.
func Parse(r *http.Request, lim Limits, gate FileGate) ([]Field, []File, error) {
	ct := r.Header.Get("Content-Type")
	mediaType := ""
	if ct != "" {
		mt, _, err := mime.ParseMediaType(ct)
		if err != nil {
			return nil, nil, ErrUnsupportedType
		}
		mediaType = mt
	}
	c := &collector{lim: lim, index: map[string]int{}}
	var err error
	switch mediaType {
	case "application/json":
		err = parseJSON(r.Body, c)
	case "multipart/form-data":
		err = parseMultipart(r, c, gate)
	case "application/x-www-form-urlencoded", "":
		err = parseURLEncoded(r.Body, c)
	default:
		return nil, nil, ErrUnsupportedType
	}
	if err != nil {
		return nil, nil, err
	}
	return c.fields, c.files, nil
}

// collector accumulates fields, keeping the order of first appearance.
// A repeated name (checkboxes, multiple selection) merges its values.
type collector struct {
	lim    Limits
	fields []Field
	index  map[string]int

	files     []File
	fileLim   FileLimits
	fileBytes int64
	gated     bool
}

func (c *collector) add(name, value string) error {
	name = strings.TrimSuffix(strings.TrimSpace(clean(name)), "[]")
	if name == "" {
		return nil
	}
	value = strings.TrimSpace(clean(value))
	if len(name) > c.lim.MaxNameLen || len(value) > c.lim.MaxValueLen {
		return ErrFieldTooLong
	}
	if i, ok := c.index[name]; ok {
		if value == "" {
			return nil
		}
		if c.fields[i].Value != "" {
			value = c.fields[i].Value + ", " + value
		}
		if len(value) > c.lim.MaxValueLen {
			return ErrFieldTooLong
		}
		c.fields[i].Value = value
		return nil
	}
	if len(c.fields) >= c.lim.MaxFields {
		return ErrTooManyFields
	}
	c.index[name] = len(c.fields)
	c.fields = append(c.fields, Field{Name: name, Value: value})
	return nil
}

// clean returns a string safe to display: valid UTF-8, normalized line endings,
// no control characters except line feed and tab.
func clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		switch {
		case r == '\n' || r == '\t':
			return r
		case r == '\r':
			return '\n'
		case r < 0x20 || r == 0x7f:
			return -1
		}
		return r
	}, s)
}

func parseURLEncoded(body io.Reader, c *collector) error {
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	for _, pair := range strings.Split(string(raw), "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		name, err := url.QueryUnescape(k)
		if err != nil {
			return ErrMalformed
		}
		value, err := url.QueryUnescape(v)
		if err != nil {
			return ErrMalformed
		}
		if err := c.add(name, value); err != nil {
			return err
		}
	}
	return nil
}

func (c *collector) addFile(part *multipart.Part, gate FileGate) error {
	if !c.gated {
		c.gated = true
		if gate != nil {
			seen, _ := Split(c.fields)
			lim, err := gate(seen)
			if err != nil {
				return err
			}
			c.fileLim = lim
		}
	}
	if c.fileLim.MaxFiles == 0 {
		return nil // ignored file: never read nor kept
	}
	if len(c.files) >= c.fileLim.MaxFiles {
		return ErrTooManyFiles
	}
	// Bounded read: one byte more than what remains allowed is enough to detect the overflow.
	left := c.fileLim.MaxBytes - c.fileBytes
	data, err := io.ReadAll(io.LimitReader(part, left+1))
	if err != nil {
		return asBodyError(err)
	}
	if int64(len(data)) > left {
		return ErrFilesTooLarge
	}
	name := fileName(part.FileName())
	if len(name) > maxFileNameLen {
		return ErrFieldTooLong
	}
	if err := c.add(part.FormName(), name); err != nil {
		return err
	}
	c.fileBytes += int64(len(data))
	c.files = append(c.files, File{Name: name, Data: data})
	return nil
}

// fileName reduces a file name to a displayable line. Formatting characters are removed:
// a change of text direction would display "invoice.pdf" for a file ending in ".exe".
func fileName(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Cf, r) || (r >= 0x80 && r <= 0x9f) {
			return -1
		}
		return r
	}, clean(s))
	if s = strings.Join(strings.Fields(s), " "); s != "" {
		return s
	}
	return "sans-nom"
}

func parseMultipart(r *http.Request, c *collector, gate FileGate) error {
	mr, err := r.MultipartReader()
	if err != nil {
		return ErrMalformed
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return asBodyError(err)
		}
		if part.FileName() != "" {
			if err := c.addFile(part, gate); err != nil {
				return err
			}
			continue
		}
		// Bounded read: one byte over the limit is enough to detect it.
		value, err := io.ReadAll(io.LimitReader(part, int64(c.lim.MaxValueLen)+1))
		if err != nil {
			return asBodyError(err)
		}
		if err := c.add(part.FormName(), string(value)); err != nil {
			return err
		}
	}
}

// asBodyError lets the size overflow (413) and the read timeout (408) through.
// Anything else is an invalid body.
func asBodyError(err error) error {
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) || errors.Is(err, os.ErrDeadlineExceeded) {
		return err
	}
	return ErrMalformed
}

func parseJSON(body io.Reader, c *collector) error {
	dec := json.NewDecoder(body)
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return asBodyError(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return ErrMalformed // only a top-level object describes a form
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return asBodyError(err)
		}
		name, ok := keyTok.(string)
		if !ok {
			return ErrMalformed
		}
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return asBodyError(err)
		}
		if err := c.add(name, jsonValue(raw)); err != nil {
			return err
		}
	}
	if _, err := dec.Token(); err != nil {
		return asBodyError(err)
	}
	return nil
}

// jsonValue flattens a JSON value: scalar as text, list of scalars joined by commas,
// any other structure as compact JSON.
func jsonValue(raw json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return string(raw)
	}
	if s, ok := scalar(v); ok {
		return s
	}
	if list, ok := v.([]any); ok {
		parts := make([]string, 0, len(list))
		for _, item := range list {
			s, ok := scalar(item)
			if !ok {
				parts = nil
				break
			}
			parts = append(parts, s)
		}
		if parts != nil {
			return strings.Join(parts, ", ")
		}
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return string(raw)
	}
	return buf.String()
}

func scalar(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", true
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	case bool:
		return strconv.FormatBool(t), true
	}
	return "", false
}

// Meta groups the service fields: they drive processing and are not part of the visitor's data.
type Meta struct {
	AccessKey string // form key, if it is not in the URL
	Redirect  string // return page requested after a submission without JavaScript
	Subject   string
	ReplyTo   string
	Captcha   string
	Bot       bool // honeypot field filled: automated submission
}

const (
	fieldAccessKey = "access_key"
	fieldRedirect  = "redirect"
	fieldSubject   = "subject"
	fieldReplyTo   = "replyto"
	fieldBotcheck  = "botcheck"
	fieldCaptcha   = "naria_captcha"
)

// Anti-bot widget tokens, never kept once the request is received.
var captchaFields = map[string]bool{
	"cf-turnstile-response": true,
	"g-recaptcha-response":  true,
	"h-captcha-response":    true,
}

func Split(fields []Field) (Meta, []Field) {
	var m Meta
	data := make([]Field, 0, len(fields))
	for _, f := range fields {
		switch f.Name {
		case fieldAccessKey:
			m.AccessKey = f.Value
		case fieldRedirect:
			m.Redirect = f.Value
		case fieldSubject:
			m.Subject = f.Value
		case fieldReplyTo:
			m.ReplyTo = f.Value
		case fieldCaptcha:
			m.Captcha = f.Value
		case fieldBotcheck:
			m.Bot = f.Value != "" && f.Value != "false" && f.Value != "0"
		default:
			if !captchaFields[f.Name] {
				data = append(data, f)
			}
		}
	}
	return m, data
}

// ReplyAddress picks the reply address: the "replyto" field, otherwise the "email" field.
// Returns "" if neither is a valid bare address, which also rules out header injection.
func ReplyAddress(m Meta, data []Field) string {
	if addr, ok := ValidEmail(m.ReplyTo); ok {
		return addr
	}
	for _, f := range data {
		if strings.EqualFold(f.Name, "email") {
			if addr, ok := ValidEmail(f.Value); ok {
				return addr
			}
		}
	}
	return ""
}

// ValidEmail validates a bare email address (without display name) and returns it normalized.
func ValidEmail(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 254 || strings.ContainsAny(s, "\r\n<>\"(), ") {
		return "", false
	}
	addr, err := mail.ParseAddress(s)
	if err != nil || addr.Address != s {
		return "", false
	}
	return addr.Address, true
}

// Encode serializes the fields to JSON before encryption. HTML escaping is disabled:
// this JSON is only read back by Decode, never copied into a page.
func Encode(fields []Field) (string, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return "", err
	}
	return strings.TrimSuffix(buf.String(), "\n"), nil
}

func Decode(s string) ([]Field, error) {
	var fields []Field
	if err := json.Unmarshal([]byte(s), &fields); err != nil {
		return nil, err
	}
	return fields, nil
}
