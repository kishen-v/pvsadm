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

package images

import (
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/ppc64le-cloud/pvsadm/pkg"
	"github.com/ppc64le-cloud/pvsadm/pkg/audit"
	"github.com/ppc64le-cloud/pvsadm/pkg/client"
	"github.com/ppc64le-cloud/pvsadm/pkg/utils"
)

var Cmd = &cobra.Command{
	Use:   "images",
	Short: "Purge the PowerVS images",
	Long: `Purge the PowerVS images!
pvsadm purge --help for information
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if pkg.Options.WorkspaceName != "" {
			klog.Infof("Purge images for the workspace: %s", pkg.Options.WorkspaceName)
		} else {
			klog.Infof("Purge images for the workspace ID: %s", pkg.Options.WorkspaceID)
		}

		opt := pkg.Options

		c, err := client.NewClientWithEnv(opt.Environment)

		if err != nil {
			return err
		}

		pvmclient, err := client.NewPVMClientWithEnv(c, opt.WorkspaceID, opt.WorkspaceName, pkg.Options.Environment)
		if err != nil {
			return err
		}

		images, err := pvmclient.ImgClient.GetAllPurgeable(opt.Before, opt.Since, opt.Expr)
		if err != nil {
			return fmt.Errorf("failed to get the list of images: %v", err)
		}
		table := utils.NewTable()

		table.Render(images, []string{"href", "specifications"})
		if !opt.DryRun && len(images) != 0 {
			if opt.NoPrompt || utils.AskConfirmation(fmt.Sprintf(utils.DeletePromptMessage, "images")) {
				for _, image := range images {
					klog.Infof("Deleting image: %s with ID: %s", *image.Name, *image.ImageID)
					err = pvmclient.ImgClient.Delete(*image.ImageID)
					if err != nil {
						if opt.IgnoreErrors {
							klog.Errorf("error occurred while deleting the image: %v", err)
						} else {
							return err
						}
					}
					audit.Log("images", "delete", pvmclient.InstanceName+":"+*image.Name)
				}
			}
		}
		return nil
	},
}
