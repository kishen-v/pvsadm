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
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"k8s.io/klog/v2"

	"github.com/ppc64le-cloud/pvsadm/pkg/utils"
)

const losetupCMD = "losetup"

// setupLoop allocates the free loop device for the backing store
func setupLoop(file string) (string, error) {
	exitcode, out, err := utils.RunCMD(losetupCMD, "-f", "--show", file)
	if exitcode != 0 {
		return "", fmt.Errorf("failed to setup a loop device for file: %s, exitcode: %d, stdout: %s, err: %s", file, exitcode, out, err)
	}

	return strings.TrimSpace(out), nil
}

func removeLoop(loopPath string) error {
	exitcode, stdout, stderr := utils.RunCMD(losetupCMD, "-d", loopPath)
	if exitcode != 0 {
		return fmt.Errorf("failed to remove loop device: %s, exitcode: %d, stdout: %s, err: %s", loopPath, exitcode, stdout, stderr)
	}
	return nil
}

func partprobe(device string) error {
	exitcode, out, err := utils.RunCMD("partprobe", device)
	if exitcode != 0 {
		return fmt.Errorf("failed to partprobe: %s, exitcode: %d, stdout: %s, err: %s", device, exitcode, out, err)
	}
	return nil
}

// getPartition returns the partition number of the largest partition on the device.
// It reads partition sizes from /sys/block/<dev>/<part>/size (in 512-byte sectors),
// which requires no external tools and works without elevated privileges.
func getPartition(device string) (string, error) {
	// device is e.g. /dev/loop0 → base is "loop0"
	devName := filepath.Base(device)
	sysDir := filepath.Join("/sys/block", devName)

	entries, err := os.ReadDir(sysDir)
	if err != nil {
		return "", fmt.Errorf("failed to read sysfs for device %s: %w", device, err)
	}

	var largestPartition string
	var largestSize int64

	for _, entry := range entries {
		name := entry.Name()
		// partition entries are named e.g. loop0p1, loop0p2
		if !strings.HasPrefix(name, devName+"p") {
			continue
		}
		sizeBytes, err := os.ReadFile(filepath.Join(sysDir, name, "size"))
		if err != nil {
			continue
		}
		size, err := strconv.ParseInt(strings.TrimSpace(string(sizeBytes)), 10, 64)
		if err != nil {
			continue
		}
		if size > largestSize {
			largestSize = size
			// partition number is the suffix after the last 'p'
			largestPartition = name[strings.LastIndex(name, "p")+1:]
		}
	}

	if largestPartition == "" {
		return "", fmt.Errorf("no partition found for device: %s", device)
	}
	return largestPartition, nil
}

// growpart resizes the partition
func growpart(device, partition string) error {
	exitcode, out, err := utils.RunCMD("growpart", device, partition)
	if exitcode != 0 {
		return fmt.Errorf("failed to growpart for the device: %s and partition: %s, exitcode: %d, stdout: %s, err: %s", device, partition, exitcode, out, err)
	}
	return nil
}

// getFSType returns the filesystem type for the given device and the partition
func getFSType(device string) (string, error) {
	exitcode, out, err := utils.RunCMD("blkid", device, "-o", "value", "-s", "TYPE")
	if exitcode != 0 {
		return "", fmt.Errorf("failed to get the filesystem type for the device: %s, exitcode: %d, stdout: %s, err: %s", device, exitcode, out, err)
	}
	return strings.TrimSpace(out), nil
}

func xfsGrow(device string) error {
	exitcode, out, err := utils.RunCMD("xfs_growfs", "-d", device)
	if exitcode != 0 {
		return fmt.Errorf("failed to xfs_growfs device: %s, exitcode: %d, stdout: %s, err: %s", device, exitcode, out, err)
	}
	return nil
}

func resize2fs(device string) error {
	exitcode, out, err := utils.RunCMD("resize2fs", device)
	if exitcode != 0 {
		return fmt.Errorf("failed to resize2fs the device: %s, exitcode: %d, stdout: %s, err: %s", device, exitcode, out, err)
	}
	return nil
}

func mount(opts, src, target string) error {
	exitcode, out, err := utils.RunCMD("mount", "-o", opts, src, target)
	if exitcode != 0 {
		return fmt.Errorf("failed to bind mount, source: %s and target: %s, exitcode: %d, stdout: %s, err: %s", src, target, exitcode, out, err)
	}
	return nil
}

// checkFileExists return True if file with the name exists else False
func checkFileExists(name string) (bool, error) {
	matches, err := filepath.Glob(name)
	return len(matches) > 0, err
}

// bootDeviceuuid takes fstab file path as input and returns uuid of boot device
func bootDeviceuuid(file string) (string, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return "", err
	}
	deviceuuid := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[1] == "/boot" && strings.HasPrefix(fields[0], "UUID=") {
			parts := strings.Split(fields[0], "=")
			if len(parts) > 1 {
				deviceuuid = parts[1]
			}
		}
	}
	return deviceuuid, nil
}

// findDevice takes UUID as input and returns the device/partition associated with it.
func findDevice(uuid string) (string, error) {
	exitcode, out, err := utils.RunCMD("blkid", "--uuid", uuid)
	if exitcode != 0 {
		return "", fmt.Errorf("failed to get the device name, exitcode: %d, stdout: %s, err: %s", exitcode, out, err)
	}
	return strings.TrimSpace(out), nil
}

func Umount(dir string) error {
	exitcode, out, err := utils.RunCMD("umount", dir)
	if exitcode != 0 {
		if strings.Contains(err, "not mounted") {
			klog.V(1).Infof("Ignoring 'not mounted' error for %s", dir)
			return nil
		}
		if strings.Contains(err, "no mount point specified") {
			klog.V(1).Infof("Ignoring 'no mount point specified' error for %s", dir)
			return nil
		}
		if strings.Contains(err, "target is busy") {
			for retry := 0; retry < 5; retry++ {
				exitcode, _, err = utils.RunCMD("umount", dir)
				if exitcode == 0 || strings.Contains(err, "no mount point specified") || strings.Contains(err, "not mounted") {
					return nil
				}
			}
			klog.V(1).Infof("As '%s' is busy, unmounting it using lazy unmount", dir)
			exitcode, out, err = utils.RunCMD("umount", "-lf", dir)
			if exitcode == 0 {
				return nil
			}
		}
		return fmt.Errorf("failed to unmount, dir: %s, exitcode: %d, stdout: %s, err: %s", dir, exitcode, out, err)
	}
	return nil
}
