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

package ports

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/ppc64le-cloud/pvsadm/pkg"
	"github.com/ppc64le-cloud/pvsadm/pkg/client"
	"github.com/ppc64le-cloud/pvsadm/pkg/utils"
)

var (
	network string
)

var Cmd = &cobra.Command{
	Use:   "ports",
	Short: "Get PowerVS network ports",
	Long:  `Get PowerVS network ports`,
	PreRunE: func(cmd *cobra.Command, args []string) error {
		return utils.EnsureWorkspaceIDorNameIsSet(pkg.Options.WorkspaceID, pkg.Options.WorkspaceName)
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		opt := pkg.Options

		c, err := client.NewClientWithEnv(opt.Environment)
		if err != nil {
			klog.Errorf("failed to create a session with IBM cloud, err: %v", err)
			return err
		}

		pvmclient, err := client.NewPVMClientWithEnv(c, opt.WorkspaceID, opt.WorkspaceName, opt.Environment)
		if err != nil {
			return err
		}

		networks, err := pvmclient.NetworkClient.GetAll()
		if err != nil {
			return fmt.Errorf("failed to get the networks, err: %v", err)
		}

		var networkNames, networkIDs []string
		for _, net := range networks.Networks {
			networkIDs = append(networkIDs, *net.NetworkID)
			networkNames = append(networkNames, *net.Name)
		}

		var netID string

		if utils.Contains(networkIDs, network) {
			netID = network
		} else if utils.Contains(networkNames, network) {
			for _, n := range networks.Networks {
				if *n.Name == network {
					netID = *n.NetworkID
				}
			}
		} else {
			return fmt.Errorf("not able to find network: \"%s\" by ID or name in the list: ids:[%s], names: [%s]", network, strings.Join(networkIDs, ","), strings.Join(networkNames, ","))
		}

		ports, err := pvmclient.NetworkClient.GetAllPorts(netID)
		if err != nil {
			return fmt.Errorf("failed to get the ports, err: %v", err)
		}

		table := utils.NewTable()
		table.Render(ports.Ports, []string{"href", "pvminstance"})
		return nil
	},
}

func init() {
	Cmd.Flags().StringVar(&network, "network", "", "Network ID or Name(preference will be given to the ID over Name)")
	_ = Cmd.MarkFlagRequired("network")
}
