package config

import (
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
)

const envVarPrefix = "HEPLIFY_"

// EnvFieldMapping represents a mapping between environment variable name and field path.
type EnvFieldMapping struct {
	EnvName   string
	FieldPath string
	FieldType string
}

// EnvUpdater handles updating Config from environment variables using reflection.
// It supports all field types including nested structs and slices, using the
// HEPLIFY_ prefix and double-underscore (__) as array index delimiters.
//
// Examples:
//
//	HEPLIFY_TRANSPORT__0__HOST=127.0.0.1
//	HEPLIFY_SIP_SETTINGS_DISCARD_METHODS__0=REGISTER
//	HEPLIFY_LOG_SETTINGS_LEVEL=debug
type EnvUpdater struct {
	fieldMappings []EnvFieldMapping
	initialized   bool
}

// NewEnvUpdater creates a new EnvUpdater instance.
func NewEnvUpdater() *EnvUpdater {
	return &EnvUpdater{
		fieldMappings: []EnvFieldMapping{},
	}
}

// Initialize builds the full list of ENV-variable → field-path mappings by
// walking the Config struct recursively via reflection.
func (eu *EnvUpdater) Initialize() error {
	if eu.initialized {
		return nil
	}

	fields := extractFields(Config{}, "")

	eu.fieldMappings = make([]EnvFieldMapping, 0, len(fields))
	for _, f := range fields {
		if f.MapstructureTag != "" && f.MapstructureTag != "-" {
			eu.fieldMappings = append(eu.fieldMappings, EnvFieldMapping{
				EnvName:   f.FullPath,
				FieldPath: f.FullPath,
				FieldType: f.Type,
			})
		}
	}

	eu.initialized = true
	return nil
}

// UpdateFromEnv applies all matching HEPLIFY_* environment variables to cfg.
// Returns the number of fields updated and any error.
func (eu *EnvUpdater) UpdateFromEnv(cfg *Config) (int, error) {
	if !eu.initialized {
		if err := eu.Initialize(); err != nil {
			return 0, err
		}
	}

	// First pass: collect paths that reference array indices and ensure the
	// slices are large enough before we start assigning values.
	pathsWithIndices := make(map[string]bool)
	for _, m := range eu.fieldMappings {
		if _, exists := os.LookupEnv(m.EnvName); exists {
			if strings.Contains(m.FieldPath, "__") {
				pathsWithIndices[m.FieldPath] = true
			}
		}
	}
	eu.initializeArraysForPaths(cfg, pathsWithIndices)

	// Second pass: set values.
	updated := 0
	for _, m := range eu.fieldMappings {
		if v, exists := os.LookupEnv(m.EnvName); exists {
			if eu.updateFieldByPath(cfg, m.FieldPath, v) {
				updated++
			}
		}
	}

	// Remove empty strings that may have been introduced when clearing slice elements.
	eu.removeEmptyStringsFromSlices(cfg)

	return updated, nil
}

// GetFieldMappingsCount returns the total number of mapped ENV variables.
func (eu *EnvUpdater) GetFieldMappingsCount() int {
	return len(eu.fieldMappings)
}

// PrintFieldMappings prints the first few field mappings for debugging.
func (eu *EnvUpdater) PrintFieldMappings() {
	if !eu.initialized {
		fmt.Println("EnvUpdater not initialized")
		return
	}
	fmt.Printf("Total field mappings: %d\n", len(eu.fieldMappings))
	for i, m := range eu.fieldMappings {
		if i >= 10 {
			fmt.Printf("  ... and %d more\n", len(eu.fieldMappings)-10)
			break
		}
		fmt.Printf("  %s (%s)\n", m.EnvName, m.FieldType)
	}
}

// initializeArraysForPaths ensures that slices referenced by ENV paths are
// pre-allocated to the required length before values are assigned.
func (eu *EnvUpdater) initializeArraysForPaths(cfg *Config, pathsWithIndices map[string]bool) {
	for path := range pathsWithIndices {
		parts := splitEnvPath(strings.TrimPrefix(path, envVarPrefix))
		if len(parts) > 0 {
			eu.ensureArrayIndex(cfg, parts)
		}
	}
}

// ensureArrayIndex walks the struct following parts and grows any slice it
// encounters so that the referenced index will be valid.
func (eu *EnvUpdater) ensureArrayIndex(cfg *Config, parts []string) {
	cur := reflect.ValueOf(cfg).Elem()

	i := 0
	for i < len(parts) {
		part := parts[i]

		if _, err := strconv.Atoi(part); err == nil {
			// Numeric index reached — slice was already grown by the field
			// navigation above; nothing more to do here.
			return
		}

		fieldName := part
		found := false

		for j := i; j < len(parts); j++ {
			if j > i {
				fieldName += "_" + parts[j]
			}
			if cur.Kind() != reflect.Struct {
				break
			}

			for k := 0; k < cur.NumField(); k++ {
				ft := cur.Type().Field(k)
				tag := ft.Tag.Get("mapstructure")

				if !matchesField(ft.Name, tag, fieldName) {
					continue
				}

				fv := cur.Field(k)

				// If this is a slice and the next part is an index, grow it.
				if fv.Kind() == reflect.Slice && j+1 < len(parts) {
					if nextIdx, err := strconv.Atoi(parts[j+1]); err == nil {
						required := nextIdx + 1
						if fv.IsNil() || nextIdx >= fv.Len() {
							newSlice := reflect.MakeSlice(fv.Type(), required, required)
							if !fv.IsNil() {
								reflect.Copy(newSlice, fv)
							}
							if cur.Field(k).CanSet() {
								cur.Field(k).Set(newSlice)
								fv = cur.Field(k)
							}
						}
					}
				}

				cur = fv
				found = true
				i = j + 1
				break
			}
			if found {
				break
			}
		}
		if !found {
			return
		}
	}
}

// updateFieldByPath navigates cfg using the encoded path and sets the terminal
// field to value. Returns true when the assignment succeeds.
func (eu *EnvUpdater) updateFieldByPath(cfg *Config, fieldPath string, value string) bool {
	parts := splitEnvPath(strings.TrimPrefix(fieldPath, envVarPrefix))
	if len(parts) == 0 {
		return false
	}

	cur := reflect.ValueOf(cfg).Elem()

	i := 0
	for i < len(parts) {
		part := parts[i]

		if idx, err := strconv.Atoi(part); err == nil {
			if cur.Kind() != reflect.Slice || idx < 0 || idx >= cur.Len() {
				return false
			}
			cur = cur.Index(idx)
			i++
			continue
		}

		fieldName := part
		found := false

		for j := i; j < len(parts); j++ {
			if j > i {
				fieldName += "_" + parts[j]
			}
			if cur.Kind() != reflect.Struct {
				break
			}

			for k := 0; k < cur.NumField(); k++ {
				ft := cur.Type().Field(k)
				tag := ft.Tag.Get("mapstructure")

				if !matchesField(ft.Name, tag, fieldName) {
					continue
				}

				cur = cur.Field(k)
				found = true
				i = j + 1
				break
			}
			if found {
				break
			}

			// Fallback: try matching only the single current part before
			// attempting longer combined names.
			if j == i && !found {
				for k := 0; k < cur.NumField(); k++ {
					ft := cur.Type().Field(k)
					tag := ft.Tag.Get("mapstructure")
					if matchesField(ft.Name, tag, part) {
						cur = cur.Field(k)
						found = true
						i = j + 1
						break
					}
				}
				if found {
					break
				}
			}
		}
		if !found {
			return false
		}
	}

	if !cur.CanSet() {
		return false
	}

	switch cur.Kind() {
	case reflect.String:
		cur.SetString(value)
	case reflect.Bool:
		v, err := strconv.ParseBool(value)
		if err != nil {
			return false
		}
		cur.SetBool(v)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			// Keep ENV semantics aligned with CLI for buffer max-size values:
			// allow unit suffixes (KB/MB/GB/TB) for HEPLIFY_BUFFER_SETTINGS_MAX_SIZE.
			if strings.EqualFold(fieldPath, envVarPrefix+"BUFFER_SETTINGS_MAX_SIZE") {
				parsed := parseByteSize(value)
				if parsed <= 0 {
					return false
				}
				cur.SetInt(parsed)
				return true
			}
			return false
		}
		cur.SetInt(v)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return false
		}
		cur.SetUint(v)
	case reflect.Float32, reflect.Float64:
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return false
		}
		cur.SetFloat(v)
	default:
		return false
	}
	return true
}

func parseByteSize(s string) int64 {
	s = strings.ToUpper(strings.TrimSpace(s))
	multipliers := []struct {
		suffix string
		mult   int64
	}{
		{suffix: "TB", mult: 1024 * 1024 * 1024 * 1024},
		{suffix: "GB", mult: 1024 * 1024 * 1024},
		{suffix: "MB", mult: 1024 * 1024},
		{suffix: "KB", mult: 1024},
		{suffix: "B", mult: 1},
	}

	for _, m := range multipliers {
		if strings.HasSuffix(s, m.suffix) {
			numStr := strings.TrimSuffix(s, m.suffix)
			n, err := strconv.ParseInt(numStr, 10, 64)
			if err != nil {
				return 0
			}
			return n * m.mult
		}
	}

	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// removeEmptyStringsFromSlices recursively strips empty strings from all
// []string fields in cfg (used to clean up after clearing slice elements).
func (eu *EnvUpdater) removeEmptyStringsFromSlices(cfg *Config) {
	cleanStringSlicesRecursive(reflect.ValueOf(cfg).Elem())
}

func cleanStringSlicesRecursive(v reflect.Value) {
	if !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Ptr:
		if !v.IsNil() {
			cleanStringSlicesRecursive(v.Elem())
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			switch f.Kind() {
			case reflect.Slice:
				if f.Type().Elem().Kind() == reflect.String {
					compactStringSlice(f)
				} else {
					for j := 0; j < f.Len(); j++ {
						cleanStringSlicesRecursive(f.Index(j))
					}
				}
			case reflect.Struct:
				cleanStringSlicesRecursive(f)
			}
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.String {
			compactStringSlice(v)
		} else {
			for i := 0; i < v.Len(); i++ {
				cleanStringSlicesRecursive(v.Index(i))
			}
		}
	}
}

func compactStringSlice(v reflect.Value) {
	if !v.CanSet() {
		return
	}
	var keep []string
	for i := 0; i < v.Len(); i++ {
		if s := v.Index(i).String(); s != "" {
			keep = append(keep, s)
		}
	}
	n := reflect.MakeSlice(v.Type(), len(keep), len(keep))
	for i, s := range keep {
		n.Index(i).SetString(s)
	}
	v.Set(n)
}

// FieldInfo holds metadata for a single extractable struct field.
type FieldInfo struct {
	Name            string
	FullPath        string
	MapstructureTag string
	Type            string
}

// extractFields recursively walks obj and returns a FieldInfo for every leaf
// field that has a non-empty, non-"-" mapstructure tag.
// Slices of structs are expanded with indices 0..4.
// Slices of strings are expanded with indices 0..4.
func extractFields(obj interface{}, prefix string) []FieldInfo {
	var out []FieldInfo

	objVal := reflect.ValueOf(obj)
	objType := objVal.Type()

	if objType.Kind() == reflect.Ptr {
		objVal = objVal.Elem()
		objType = objVal.Type()
	}

	// Slice at top level (shouldn't normally happen but handled for safety).
	if objType.Kind() == reflect.Slice {
		elem := objType.Elem()
		if elem.Kind() == reflect.Struct {
			for i := 0; i < 5; i++ {
				idxPrefix := fmt.Sprintf("%s__%d__", prefix, i)
				out = append(out, extractFields(reflect.New(elem).Elem().Interface(), idxPrefix)...)
			}
		} else if elem.Kind() == reflect.String {
			for i := 0; i < 5; i++ {
				p := fmt.Sprintf("%s__%d", prefix, i)
				out = append(out, FieldInfo{
					Name:            fmt.Sprintf("%s[%d]", prefix, i),
					FullPath:        p,
					MapstructureTag: p,
					Type:            "string",
				})
			}
		}
		return out
	}

	if objType.Kind() != reflect.Struct {
		return out
	}

	for i := 0; i < objType.NumField(); i++ {
		field := objType.Field(i)
		fv := objVal.Field(i)

		if !fv.CanInterface() {
			continue
		}

		tag := field.Tag.Get("mapstructure")
		if tag == "" || tag == "-" {
			continue
		}

		var fullPath string
		upper := strings.ToUpper(tag)
		if prefix == "" {
			fullPath = envVarPrefix + upper
		} else if strings.HasSuffix(prefix, "__") {
			fullPath = prefix + upper
		} else {
			fullPath = prefix + "_" + upper
		}
		fullPath = strings.ReplaceAll(fullPath, ".", "_")

		switch field.Type.Kind() {
		case reflect.Slice:
			elem := field.Type.Elem()
			if elem.Kind() == reflect.Struct {
				for j := 0; j < 5; j++ {
					idxPrefix := fmt.Sprintf("%s__%d__", fullPath, j)
					out = append(out, extractFields(reflect.New(elem).Elem().Interface(), idxPrefix)...)
				}
			} else if elem.Kind() == reflect.String {
				for j := 0; j < 5; j++ {
					p := fmt.Sprintf("%s__%d", fullPath, j)
					out = append(out, FieldInfo{
						Name:            fmt.Sprintf("%s[%d]", fullPath, j),
						FullPath:        p,
						MapstructureTag: p,
						Type:            "string",
					})
				}
			}
		case reflect.Struct:
			out = append(out, extractFields(fv.Interface(), fullPath)...)
		default:
			out = append(out, FieldInfo{
				Name:            field.Name,
				FullPath:        fullPath,
				MapstructureTag: tag,
				Type:            field.Type.Kind().String(),
			})
		}
	}
	return out
}

// splitEnvPath converts a stripped ENV key into navigation parts.
// Double underscores delimit array indices; single underscores separate
// field name components.
//
// e.g. "TRANSPORT__0__HOST"       → ["TRANSPORT", "0", "HOST"]
//
//	"SIP_SETTINGS_LEVEL"         → ["SIP", "SETTINGS", "LEVEL"]
//	"SIP_SETTINGS_DISCARD__0"    → ["SIP", "SETTINGS", "DISCARD", "0"]
func splitEnvPath(path string) []string {
	if !strings.Contains(path, "__") {
		return strings.Split(path, "_")
	}

	segments := strings.Split(path, "__")
	var parts []string
	for _, seg := range segments {
		if _, err := strconv.Atoi(seg); err == nil {
			parts = append(parts, seg)
		} else {
			parts = append(parts, strings.Split(seg, "_")...)
		}
	}
	return parts
}

// matchesField returns true when fieldName (case-insensitive) matches either
// the Go field name or the mapstructure tag value.
func matchesField(goName, tag, fieldName string) bool {
	upper := strings.ToUpper(fieldName)
	if strings.ToUpper(goName) == upper {
		return true
	}
	if tag != "" && tag != "-" && strings.EqualFold(tag, fieldName) {
		return true
	}
	return false
}
