package composite

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/threatwinds/go-sdk/store"
)

// SecondaryValueRewrite returns a Config.SecondaryValue that swaps a filter's
// value when its field is named in m and that value has an entry: "Open" becomes
// "2" before it reaches a secondary that keeps status as a numeric code. A field
// not in m, or a value with no entry, passes through unchanged, so the hook is
// safe to install even when nothing needs remapping. The map keys on the
// secondary's field name, since the hook runs after SecondaryField has remapped
// the name; only a field's own table is consulted for its values.
func SecondaryValueRewrite(m map[string]map[string]string) func(store.Filter) store.Filter {
	if len(m) == 0 {
		return nil
	}
	rewrite := func(field, v string) (string, bool) {
		vm, ok := m[field]
		if !ok {
			return v, false
		}
		nv, hit := vm[v]
		return nv, hit
	}
	return func(f store.Filter) store.Filter {
		switch v := f.Value.(type) {
		case string:
			if nv, hit := rewrite(f.Field, v); hit {
				f.Value = nv
			}
		case []string:
			for i, e := range v {
				if nv, hit := rewrite(f.Field, e); hit {
					v[i] = nv
				}
			}
			f.Value = v
		case []any:
			for i, e := range v {
				if s, ok := e.(string); ok {
					if nv, hit := rewrite(f.Field, s); hit {
						v[i] = nv
					}
				}
			}
			f.Value = v
		case [2]any:
			if s, ok := v[0].(string); ok {
				if nv, hit := rewrite(f.Field, s); hit {
					v[0] = nv
				}
			}
			if s, ok := v[1].(string); ok {
				if nv, hit := rewrite(f.Field, s); hit {
					v[1] = nv
				}
			}
			f.Value = v
		}
		return f
	}
}

// PrefixMap returns the two field-name translations a Config takes, for stores
// that differ only in what they call the object holding the parsed fields: the
// current store says "log.user" where the secondary says "event.user". Names that
// do not start with the prefix pass through unchanged, and so does the prefix
// alone.
func PrefixMap(primary, secondary string) (toSecondary, fromSecondary func(string) string) {
	swap := func(from, to string) func(string) string {
		return func(field string) string {
			if field == from {
				return to
			}
			if rest, ok := strings.CutPrefix(field, from+"."); ok {
				return to + "." + rest
			}
			return field
		}
	}
	return swap(primary, secondary), swap(secondary, primary)
}

// RenameDocKey returns a Config.SecondaryDocument that renames one top-level key of
// a record. A record without the key, or that is not a JSON object, is returned
// as it came, and a key already present under the new name is left alone.
func RenameDocKey(from, to string) func(json.RawMessage) json.RawMessage {
	return func(doc json.RawMessage) json.RawMessage {
		var top map[string]json.RawMessage
		if err := json.Unmarshal(doc, &top); err != nil {
			return doc
		}
		v, ok := top[from]
		if !ok {
			return doc
		}
		if _, exists := top[to]; !exists {
			top[to] = v
		}
		delete(top, from)

		out, err := json.Marshal(top)
		if err != nil {
			return doc
		}
		return out
	}
}

// DocRewrite is what a Config.SecondaryDocument can do to a record coming back
// from the secondary, all in one decode pass: rename the top-level key the
// stores disagree on, reformat a date field into the primary's layout, and
// swap the values of fields the two stores name the same but keep in
// different forms. A field or key absent from a record leaves it alone; a
// record that is not a JSON object comes back as it came.
type DocRewrite struct {
	// RenameFrom and RenameTo swap one top-level key, the secondary's name for
	// the primary's. RenameTo empty means no rename; a key already present
	// under RenameTo wins.
	RenameFrom, RenameTo string
	// TimeField and TimeLayout reformat one field's RFC 3339 date into the
	// layout the primary renders ("2006-01-02 15:04:05.000"). TimeField empty
	// means no reformat; a value that does not parse passes through.
	TimeField, TimeLayout string
	// Values maps a field's value, as the secondary keeps it, to the form the
	// primary uses, so records read like the primary's.
	Values map[string]map[string]string
}

func (r DocRewrite) Apply(doc json.RawMessage) json.RawMessage {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(doc, &top); err != nil {
		return doc
	}
	changed := false

	if r.RenameFrom != "" {
		v, ok := top[r.RenameFrom]
		if ok {
			if _, exists := top[r.RenameTo]; exists {
				delete(top, r.RenameFrom)
			} else {
				top[r.RenameTo] = v
				delete(top, r.RenameFrom)
			}
			changed = true
		}
	}

	if r.TimeField != "" {
		if raw, ok := top[r.TimeField]; ok {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
					top[r.TimeField], _ = json.Marshal(t.UTC().Format(r.TimeLayout))
					changed = true
				}
			}
		}
	}

	for field, m := range r.Values {
		raw, ok := top[field]
		if !ok {
			continue
		}
		var s string
		if json.Unmarshal(raw, &s) != nil {
			continue
		}
		if nv, hit := m[s]; hit {
			top[field], _ = json.Marshal(nv)
			changed = true
		}
	}

	if !changed {
		return doc
	}
	out, err := json.Marshal(top)
	if err != nil {
		return doc
	}
	return out
}
