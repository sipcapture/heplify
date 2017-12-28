/*
Copyright (c) 2012–2017 Elastic <http://www.elastic.co>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package configure

import (
	"flag"
	"strings"
)

// StringsFlag collects multiple usages of the same flag into an array of strings.
// Duplicate values will be ignored.
type StringsFlag struct {
	list      *[]string
	isDefault bool
	flag      *flag.Flag
}

func init() {
	StringArrVarFlag(nil, &debugSelectors, "d", "Enable certain debug selectors [*,fragment,layer,payload,rtcp,rtcpfail,sdp]")
}

// StringArrFlag creates and registers a new StringsFlag with the given FlagSet.
// If no FlagSet is passed, flag.CommandLine will be used as target FlagSet.
func StringArrFlag(fs *flag.FlagSet, name, def, usage string) *StringsFlag {
	var arr *[]string
	if def != "" {
		arr = &[]string{def}
	} else {
		arr = &[]string{}
	}

	return StringArrVarFlag(fs, arr, name, usage)
}

// StringArrVarFlag creates and registers a new StringsFlag with the given
// FlagSet.  Results of the flag usage will be appended to `arr`. If the slice
// is not initially empty, its first value will be used as default. If the flag
// is used, the slice will be emptied first.  If no FlagSet is passed,
// flag.CommandLine will be used as target FlagSet.
func StringArrVarFlag(fs *flag.FlagSet, arr *[]string, name, usage string) *StringsFlag {
	if fs == nil {
		fs = flag.CommandLine
	}
	f := NewStringsFlag(arr)
	f.Register(fs, name, usage)
	return f
}

// NewStringsFlag creates a new, but unregistered StringsFlag instance.
// Results of the flag usage will be appended to `arr`. If the slice is not
// initially empty, its first value will be used as default. If the flag is
// used, the slice will be emptied first.
func NewStringsFlag(arr *[]string) *StringsFlag {
	if arr == nil {
		panic("No target array")
	}
	return &StringsFlag{list: arr, isDefault: true}
}

// Register registers the StringsFlag instance with a FlagSet.
// A valid FlagSet must be used.
// Register panics if the flag is already registered.
func (f *StringsFlag) Register(fs *flag.FlagSet, name, usage string) {
	if f.flag != nil {
		panic("StringsFlag is already registered")
	}

	fs.Var(f, name, usage)
	f.flag = fs.Lookup(name)
	if f.flag == nil {
		panic("Failed to lookup registered flag")
	}

	if len(*f.list) > 0 {
		f.flag.DefValue = (*f.list)[0]
	}
}

// String joins all it's values set into a comma-separated string.
func (f *StringsFlag) String() string {
	if f == nil || f.list == nil {
		return ""
	}

	l := *f.list
	return strings.Join(l, ", ")
}

// SetDefault sets the flags new default value.
// This overwrites the contents in the backing array.
func (f *StringsFlag) SetDefault(v string) {
	if f.flag != nil {
		f.flag.DefValue = v
	}

	*f.list = []string{v}
	f.isDefault = true
}

// Set is used to pass usage of the flag to StringsFlag. Set adds the new value
// to the backing array. The array will be emptied on Set, if the backing array
// still contains the default value.
func (f *StringsFlag) Set(v string) error {
	// Ignore duplicates, can be caused by multiple flag parses
	if f.isDefault {
		*f.list = []string{v}
	} else {
		for _, old := range *f.list {
			if old == v {
				return nil
			}
		}
		*f.list = append(*f.list, v)
	}
	f.isDefault = false
	return nil
}

// Get returns the backing slice its contents as interface{}. The type used is
// `[]string`.
func (f *StringsFlag) Get() interface{} {
	return f.List()
}

// List returns the current set values.
func (f *StringsFlag) List() []string {
	return *f.list
}

// Type reports the type of contents (string) expected to be parsed by Set.
// It is used to build the CLI usage string.
func (f *StringsFlag) Type() string {
	return "string"
}
