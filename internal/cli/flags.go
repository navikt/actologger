package cli

import (
	"strings"
)

type stringListValue struct {
	items []string
	seen  map[string]struct{}
}

func newStringListValue() *stringListValue {
	return &stringListValue{
		seen: make(map[string]struct{}),
	}
}

func (v *stringListValue) String() string {
	return strings.Join(v.items, ",")
}

func (v *stringListValue) Set(raw string) error {
	for _, part := range strings.Split(raw, ",") {
		item := strings.TrimSpace(part)
		if item == "" {
			continue
		}

		if _, ok := v.seen[item]; ok {
			continue
		}

		v.seen[item] = struct{}{}
		v.items = append(v.items, item)
	}

	return nil
}

func (v *stringListValue) Values() []string {
	out := make([]string, len(v.items))
	copy(out, v.items)
	return out
}
