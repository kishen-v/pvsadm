// Copyright 2022 IBM Corp
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

package client

import (
	"errors"

	"github.com/IBM/platform-services-go-sdk/iamidentityv1"
	"github.com/IBM/platform-services-go-sdk/resourcecontrollerv2"
)

const (
	DefaultEnvProd = "prod"
	TPEndpoint     = "TPEndpoint"
	PIEndpoint     = "PIEndpoint"
	RCEndpoint     = "RCEndpoint"
)

var ErrEnvironmentNotFound = errors.New("error environment not found")

var Environments = map[string]map[string]string{
	"test": {
		TPEndpoint: "https://iam.test.cloud.ibm.com",
		RCEndpoint: "https://resource-controller.test.cloud.ibm.com",
		PIEndpoint: "power-iaas.test.cloud.ibm.com",
	},
	"prod": {
		TPEndpoint: iamidentityv1.DefaultServiceURL,
		RCEndpoint: resourcecontrollerv2.DefaultServiceURL,
		PIEndpoint: "power-iaas.cloud.ibm.com",
	},
}

func ListEnvironments() (keys []string) {
	for k := range Environments {
		keys = append(keys, k)
	}
	return
}

func GetEnvironment(env string) (map[string]string, error) {
	if _, ok := Environments[env]; !ok {
		return nil, ErrEnvironmentNotFound
	}
	return Environments[env], nil
}

func NewPVMClientWithEnv(c *Client, instanceID, instanceName, env string) (*PVMClient, error) {
	e, err := GetEnvironment(env)
	if err != nil {
		return nil, err
	}
	return NewPVMClient(c, instanceID, instanceName, e)
}

func NewClientWithEnv(env string) (*Client, error) {
	e, err := GetEnvironment(env)
	if err != nil {
		return nil, err
	}
	return NewClient(e)
}
