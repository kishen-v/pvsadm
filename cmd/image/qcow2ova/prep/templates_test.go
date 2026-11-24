// Copyright 2021 IBM Corp
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

package prep

import (
	"strings"
	"testing"
)

func TestRender(t *testing.T) {
	type args struct {
		dist       string
		rhnuser    string
		rhnpasswd  string
		rootpasswd string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
		notwant string
	}{
		{
			name:    "rhel image",
			args:    args{"rhel", "rhn", "rhnpassword", "some-password"},
			want:    "subscription-manager",
			wantErr: false,
		},
		{
			name:    "centos image",
			args:    args{dist: "centos", rootpasswd: "some-password"},
			want:    "some-password",
			wantErr: false,
		},
		{
			name:    "rhel image without root password",
			args:    args{dist: "rhel", rhnuser: "rhn", rhnpasswd: "rhnpassword"},
			want:    "subscription-manager",
			wantErr: false,
			notwant: "passwd root",
		},
		{
			name:    "ubuntu image with root password",
			args:    args{dist: "ubuntu", rootpasswd: "some-password"},
			want:    "root:some-password",
			wantErr: false,
			notwant: "subscription-manager",
		},
		{
			name:    "ubuntu image packages",
			args:    args{dist: "ubuntu"},
			want:    "powerpc-utils",
			wantErr: false,
			notwant: "yum",
		},
		{
			name:    "ubuntu image rsct packages",
			args:    args{dist: "ubuntu"},
			want:    "ppa:ibmpackages/rsct",
			wantErr: false,
			notwant: "subscription-manager",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Render(tt.args.dist, tt.args.rhnuser, tt.args.rhnpasswd, tt.args.rootpasswd)
			if (err != nil) != tt.wantErr {
				t.Errorf("Render() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("Render() %s does not contain the %s", got, tt.want)
			}
			if tt.notwant != "" && strings.Contains(got, tt.notwant) {
				t.Errorf("Render() %s contain the %s", got, tt.notwant)
			}
		})
	}
}

func TestRenderCloudConfig(t *testing.T) {
	tests := []struct {
		dist    string
		want    string
		notwant string
	}{
		{
			dist:    "ubuntu",
			want:    "name: ubuntu",
			notwant: "name: cloud-user",
		},
		{
			dist:    "rhel",
			want:    "name: cloud-user",
			notwant: "name: ubuntu",
		},
		{
			dist:    "centos",
			want:    "name: cloud-user",
			notwant: "name: ubuntu",
		},
	}
	for _, tt := range tests {
		t.Run(tt.dist, func(t *testing.T) {
			got, err := RenderCloudConfig(tt.dist)
			if err != nil {
				t.Fatalf("RenderCloudConfig() error = %v", err)
			}
			if !strings.Contains(got, tt.want) {
				t.Errorf("RenderCloudConfig() %s does not contain %s", got, tt.want)
			}
			if tt.notwant != "" && strings.Contains(got, tt.notwant) {
				t.Errorf("RenderCloudConfig() %s contains %s", got, tt.notwant)
			}
		})
	}
}
