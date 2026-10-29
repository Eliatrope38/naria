package submission

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestTakeHoneypot(t *testing.T) {
	data := func() []Field { return []Field{{"name", "Ada"}, {"fax", ""}, {"message", "bonjour"}} }
	for _, c := range []struct {
		name   string
		in     []Field
		trap   string
		want   []Field
		filled bool
	}{
		{"no trap", data(), "", data(), false},
		{"empty trap", data(), "fax", []Field{{"name", "Ada"}, {"message", "bonjour"}}, false},
		{"filled trap", []Field{{"fax", "on"}, {"message", "spam"}}, "fax", []Field{{"message", "spam"}}, true},
		{"checkbox off", []Field{{"fax", "false"}, {"fax", "0"}}, "fax", []Field{}, false},
		{"case differs", []Field{{"Fax", "on"}}, "fax", []Field{{"Fax", "on"}}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, filled := TakeHoneypot(c.in, c.trap)
			if !reflect.DeepEqual(got, c.want) || filled != c.filled {
				t.Errorf("got %v, %v; want %v, %v", got, filled, c.want, c.filled)
			}
		})
	}
}

func TestHoneypotNameError(t *testing.T) {
	for name, want := range map[string]error{
		"fax":                   nil,
		"ref-client_2":          nil,
		strings.Repeat("a", 40): nil,
		strings.Repeat("a", 41): ErrHoneypotFormat,
		"":                      ErrHoneypotFormat,
		"2fax":                  ErrHoneypotFormat,
		"fax number":            ErrHoneypotFormat,
		`fax"><script>`:         ErrHoneypotFormat,
		"botcheck":              ErrHoneypotReserved,
		"EMAIL":                 ErrHoneypotReserved,
		"access_key":            ErrHoneypotReserved,
		"cf-turnstile-response": ErrHoneypotReserved,
	} {
		if err := HoneypotNameError(name); !errors.Is(err, want) {
			t.Errorf("%q: got %v, want %v", name, err, want)
		}
	}
}

func TestHoneypotNamesAreValid(t *testing.T) {
	for _, name := range honeypotNames {
		if err := HoneypotNameError(name); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}
