// Copyright 2026 IBM Corp
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ova

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	tests := []struct {
		dist    string
		wantId  string
		wantDes string
	}{
		{"ubuntu", `ovf:id="94"`, `<ovf:Description>Ubuntu</ovf:Description>`},
		{"rhel", `ovf:id="79"`, `<ovf:Description>RHEL</ovf:Description>`},
		{"centos", `ovf:id="79"`, `<ovf:Description>CentOS</ovf:Description>`},
		{"coreos", `ovf:id="80"`, `<ovf:Description>CoreOS</ovf:Description>`},
	}

	for _, tt := range tests {
		t.Run(tt.dist, func(t *testing.T) {
			got, err := Render("test-img", "test-vol", 1024, 10, tt.dist)
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}
			if !strings.Contains(got, tt.wantId) {
				t.Errorf("Render() %s does not contain %s", got, tt.wantId)
			}
			if !strings.Contains(got, tt.wantDes) {
				t.Errorf("Render() %s does not contain %s", got, tt.wantDes)
			}
		})
	}
}

func TestRenderMeta(t *testing.T) {
	tests := []struct {
		dist    string
		want    string
	}{
		{"ubuntu", "os-type = ubuntu"},
		{"rhel", "os-type = rhel"},
		{"centos", "os-type = centos"},
		{"coreos", "os-type = coreos"},
	}

	for _, tt := range tests {
		t.Run(tt.dist, func(t *testing.T) {
			got, err := RenderMeta("test-img", tt.dist)
			if err != nil {
				t.Fatalf("RenderMeta() error = %v", err)
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("RenderMeta() %s does not contain %s", got, tt.want)
			}
		})
	}
}
