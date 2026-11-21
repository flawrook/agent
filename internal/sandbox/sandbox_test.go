// Copyright 2026 Binerals Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sandbox

import (
	"strings"
	"testing"
)

func TestRootUnderSystemd(t *testing.T) {
	const invocation = "52ebaf0c5b1547d69e2516d2a193cbe5"
	for _, c := range []struct {
		name string
		uid  int
		env  map[string]string
		want bool
	}{
		{"root with the unit's marker only: a systemd before 232 that ignored DynamicUser=", 0, map[string]string{"FLAWROOK_SERVICE": "1"}, true},
		{"root with INVOCATION_ID only: another unit, on systemd 232 or later", 0, map[string]string{"INVOCATION_ID": invocation}, true},
		{"root with both", 0, map[string]string{"FLAWROOK_SERVICE": "1", "INVOCATION_ID": invocation}, true},
		{"root with neither: the plain binary, run by hand", 0, nil, false},
		{"root with both set but empty", 0, map[string]string{"FLAWROOK_SERVICE": "", "INVOCATION_ID": ""}, false},
		{"its own user with both: the unit's DynamicUser= in effect", 61234, map[string]string{"FLAWROOK_SERVICE": "1", "INVOCATION_ID": invocation}, false},
		{"another user with neither", 1000, nil, false},
	} {
		if got := RootUnderSystemd(c.uid, func(k string) string { return c.env[k] }); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// The line names what happened and both ways out.
func TestTheRefusalSaysWhyAndHowOut(t *testing.T) {
	for _, want := range []string{
		"running as root under systemd",
		"ignored DynamicUser=",
		"Use systemd 235 or newer",
		"run the agent as a non-root user without systemd",
		"Not started.",
	} {
		if !strings.Contains(Refusal, want) {
			t.Errorf("the refusal lacks %q: %s", want, Refusal)
		}
	}
	if strings.Contains(Refusal, "\n") {
		t.Error("the refusal must be one line")
	}
}
