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

package cmd

import (
	goflag "flag"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"k8s.io/klog/v2"

	"github.com/ppc64le-cloud/pvsadm/cmd/create"
	deletecmd "github.com/ppc64le-cloud/pvsadm/cmd/delete"
	"github.com/ppc64le-cloud/pvsadm/cmd/dhcp-sync"
	"github.com/ppc64le-cloud/pvsadm/cmd/dhcpserver"
	"github.com/ppc64le-cloud/pvsadm/cmd/get"
	"github.com/ppc64le-cloud/pvsadm/cmd/image"
	"github.com/ppc64le-cloud/pvsadm/cmd/purge"
	versioncmd "github.com/ppc64le-cloud/pvsadm/cmd/version"
	"github.com/ppc64le-cloud/pvsadm/pkg"
	"github.com/ppc64le-cloud/pvsadm/pkg/audit"
	"github.com/ppc64le-cloud/pvsadm/pkg/client"
	"github.com/ppc64le-cloud/pvsadm/pkg/version"
)

var rootCmd = &cobra.Command{
	Use:     "pvsadm",
	Version: version.Version + " " + fmt.Sprintf("GoVersion: %s\n", runtime.Version()),
	Short:   "pvsadm is a command line tool for managing IBM Cloud PowerVS infrastructure",
	Long: `Power Systems Virtual Server projects deliver flexible compute capacity for Power Systems workloads.
Integrated with the IBM Cloud platform for on-demand provisioning.

This is a tool built for the Power Systems Virtual Server helps managing and maintaining the resources easily`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		if pkg.Options.APIKey == "" {
			// TODO : deprecate IBMCLOUD_API_KEY for IBMCLOUD_APIKEY
			// The GetAuthenticatorFromEnvironment requires "IBMCLOUD_APIKEY" to be set, apart from IBMCLOUD_API_KEY used in the project.
			// In order to use the resourcecontrollerv2's functionality, the IBMCLOUD_API_KEY is re-exported as IBMCLOUD_APIKEY.
			// Ref: github.com/ibm/go-sdk-core/v5@v5.17.2/core/config_utils.go, which is available from either from a credentials file, environment or VCAP service.
			if pkg.Options.APIKey = os.Getenv("IBMCLOUD_API_KEY"); pkg.Options.APIKey != "" {
				klog.Warning("IBMCLOUD_API_KEY will be deprecated in future releases. Use IBMCLOUD_APIKEY instead.")
				klog.V(1).Info("Using an API key from IBMCLOUD_API_KEY environment variable")
				os.Setenv("IBMCLOUD_APIKEY", pkg.Options.APIKey)
			}
		}
		if key := os.Getenv("IBMCLOUD_APIKEY"); key != "" {
			pkg.Options.APIKey = key
		}

		// If the API-key was set through flags, export it under IBMCLOUD_APIKEY.
		if pkg.Options.APIKey != "" {
			os.Setenv("IBMCLOUD_APIKEY", pkg.Options.APIKey)
		}

		if _, err := client.GetEnvironment(pkg.Options.Environment); err != nil {
			return fmt.Errorf("invalid \"%s\" IBM Cloud Environment passed, valid values are: %s", pkg.Options.Environment, strings.Join(client.ListEnvironments(), ", "))
		}
		return nil
	},
}

func init() {
	// Initilize the klog flags
	klog.InitFlags(nil)
	flag.CommandLine.AddGoFlagSet(goflag.CommandLine)

	rootCmd.SetVersionTemplate(`Version: {{.Version}}`)
	rootCmd.AddGroup(&cobra.Group{ID: "resource", Title: "Resource Management Commands:"})
	rootCmd.AddGroup(&cobra.Group{ID: "dhcp", Title: "DHCP Commands:"})
	rootCmd.AddGroup(&cobra.Group{ID: "image", Title: "Image Commands:"})
	rootCmd.AddGroup(&cobra.Group{ID: "admin", Title: "Administration Commands:"})
	rootCmd.SetHelpCommandGroupID("admin")
	rootCmd.SetCompletionCommandGroupID("admin")
	rootCmd.AddCommand(purge.Cmd)
	rootCmd.AddCommand(get.Cmd)
	// TODO : Remove the version command in a future release.
	rootCmd.AddCommand(versioncmd.Cmd)
	rootCmd.AddCommand(image.Cmd)
	rootCmd.AddCommand(create.Cmd)
	rootCmd.AddCommand(deletecmd.Cmd)
	rootCmd.AddCommand(dhcp.Cmd)
	rootCmd.AddCommand(dhcpserver.Cmd)
	rootCmd.PersistentFlags().StringVarP(&pkg.Options.APIKey, "api-key", "k", "", "IBMCLOUD API Key(env name: IBMCLOUD_APIKEY)")
	rootCmd.PersistentFlags().StringVar(&pkg.Options.Environment, "env", client.DefaultEnvProd, "IBM Cloud Environments, supported are: ["+strings.Join(client.ListEnvironments(), ", ")+"]")
	rootCmd.PersistentFlags().BoolVar(&pkg.Options.Debug, "debug", false, "Enable PowerVS debug option(ATTENTION: dev only option, may print sensitive data from APIs)")
	rootCmd.PersistentFlags().StringVar(&pkg.Options.AuditFile, "audit-file", "pvsadm_audit.log", "Audit logs for the tool")
	rootCmd.Flags().SortFlags = false
	rootCmd.PersistentFlags().SortFlags = false
	_ = rootCmd.Flags().MarkHidden("debug")

	// Hide the --audit-file for the image subcommand
	// TODO: Remove this after adding audit support to image subcommand
	origHelpFunc := rootCmd.HelpFunc()
	rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		if cmd.Name() == "image" || (cmd.Parent() != nil && cmd.Parent().Name() == "image") {
			cmd.Flags().MarkHidden("audit-file")
		}
		origHelpFunc(cmd, args)
	})

	audit.Logger = audit.New(pkg.Options.AuditFile)

}

func Execute() error {
	defer audit.Delete(pkg.Options.AuditFile)
	if err := rootCmd.Execute(); err != nil {
		return err
	}
	return nil
}
