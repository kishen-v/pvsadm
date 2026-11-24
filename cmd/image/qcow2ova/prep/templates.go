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
	"bytes"
	"fmt"
	"text/template"
)

// TODO: add a logic to make the package versions as an argument
var SetupTemplate = `#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

{{if eq .Dist "rhel"}}
subscription-manager register --force --auto-attach --username={{ .RHNUser }} --password={{ .RHNPassword }}
yum update -y && yum install -y yum-utils
yum install -y cloud-init
{{end}}
{{if eq .Dist "ubuntu"}}
export DEBIAN_FRONTEND=noninteractive
if [ -f /etc/apt/sources.list ] && [ ! -f /etc/apt/sources.list.orig ]; then
    cp /etc/apt/sources.list /etc/apt/sources.list.orig
fi
if [ -d /etc/apt/sources.list.d ] && [ ! -d /etc/apt/sources.list.d.orig ]; then
    cp -r /etc/apt/sources.list.d /etc/apt/sources.list.d.orig
fi
sed -i -E 's|http://|https://|g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
if ! apt-get update -o Acquire::http::Timeout=5 -o Acquire::https::Timeout=5; then
    sed -i -E 's|https?://ports.ubuntu.com/ubuntu-ports/?|https://mirrors.dotsrc.org/ubuntu-ports/|g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
    apt-get update
fi
apt-get -y upgrade
apt-get -y install software-properties-common ca-certificates
add-apt-repository -y universe || true
add-apt-repository -y ppa:ibmpackages/rsct || true
sed -i -E 's|http://|https://|g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
if ! apt-get update -o Acquire::http::Timeout=5 -o Acquire::https::Timeout=5; then
    sed -i -E 's|https?://ports.ubuntu.com/ubuntu-ports/?|https://mirrors.dotsrc.org/ubuntu-ports/|g' /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null || true
    apt-get update
fi
if ! apt-get -y install cloud-init multipath-tools powerpc-utils ppc64-diag dynamicrm devices.chrp.base.servicerm rsct.opt.storagerm rsct.core rsct.basic rsct.core.utils src; then
    echo "WARNING: RSCT packages unavailable, falling back to base packages only" >&2
    apt-get -y install cloud-init multipath-tools powerpc-utils ppc64-diag
fi
{{end}}
{{if .RootPasswd }}
{{if or (eq .Dist "rhel") (eq .Dist "centos")}}
echo {{ .RootPasswd }} | passwd root --stdin
{{else if eq .Dist "ubuntu"}}
echo "root:{{ .RootPasswd }}" | chpasswd
{{end}}
{{end}}
{{if or (eq .Dist "rhel") (eq .Dist "centos")}}
yum reinstall grub2-common -y
rm -rf /etc/systemd/system/multi-user.target.wants/firewalld.service
rpm -vih --nodeps https://public.dhe.ibm.com/software/server/POWER/Linux/yum/download/ibm-power-repo-latest.noarch.rpm
sed -i 's/^more \/opt\/ibm\/lop\/notice/#more \/opt\/ibm\/lop\/notice/g' /opt/ibm/lop/configure
echo 'y' | /opt/ibm/lop/configure
{{end}}
{{if eq .Dist "ubuntu"}}
apt-get install --reinstall -y grub-common || true
if [ -f /opt/ibm/lop/configure ]; then
    sed -i 's/^more \/opt\/ibm\/lop\/notice/#more \/opt\/ibm\/lop\/notice/g' /opt/ibm/lop/configure
    echo 'y' | /opt/ibm/lop/configure
fi
{{end}}
{{if eq .Dist "rhel"}}
# Disable the AT repository due to slowness in nature
yum-config-manager --disable Advance_Toolchain
{{end}}
{{if eq .Dist "centos"}}
yum-config-manager --add-repo=https://public.dhe.ibm.com/software/server/POWER/Linux/yum/IBM/RHEL/$(rpm -E %{rhel})/ppc64le/
rpm --import https://public.dhe.ibm.com/software/server/POWER/Linux/yum/IBM/RHEL/$(rpm -E %{rhel})/ppc64le/repodata/repomd.xml.key
{{end}}
{{if or (eq .Dist "rhel") (eq .Dist "centos")}}
yum install  powerpc-utils librtas DynamicRM  devices.chrp.base.ServiceRM rsct.opt.storagerm rsct.core rsct.basic rsct.core src -y
yum install -y device-mapper-multipath
{{end}}
cat <<EOF > /etc/multipath.conf
defaults {
    user_friendly_names yes
    verbosity 6
    polling_interval 10
    max_polling_interval 50
    reassign_maps yes
    failback immediate
    rr_min_io 2000
    no_path_retry 10
    checker_timeout 30
    find_multipaths smart
}
EOF
sed -i 's/GRUB_TIMEOUT=.*$/GRUB_TIMEOUT=60/g' /etc/default/grub
sed -i 's/GRUB_CMDLINE_LINUX=.*$/GRUB_CMDLINE_LINUX="console=tty0 console=hvc0,115200n8  biosdevname=0  crashkernel=auto rd.shell rd.debug rd.driver.pre=dm_multipath log_buf_len=1M "/g' /etc/default/grub
{{if or (eq .Dist "rhel") (eq .Dist "centos")}}
echo 'force_drivers+=" dm-multipath "' >/etc/dracut.conf.d/10-mp.conf
dracut --regenerate-all --force
for kernel in $(rpm -q kernel | sort -V | sed 's/kernel-//')
do
	echo "Generating initramfs for kernel version: ${kernel}"
	dracut --kver ${kernel} --force --add multipath --include /etc/multipath /etc/multipath --include /etc/multipath.conf /etc/multipath.conf
done
grub2-mkconfig -o /boot/grub2/grub.cfg
rm -rf /etc/sysconfig/network-scripts/ifcfg-eth0
{{end}}
{{if eq .Dist "ubuntu"}}
# Check if Ubuntu is using dracut or initramfs-tools
if command -v dracut >/dev/null 2>&1; then
    # Ubuntu with dracut (24.04+)
    echo 'force_drivers+=" dm-multipath "' >/etc/dracut.conf.d/10-mp.conf
    dracut --regenerate-all --force
    for kernel in $(ls /boot/vmlinuz-* /boot/vmlinux-* 2>/dev/null | sed -e 's/\/boot\/vmlinuz-//' -e 's/\/boot\/vmlinux-//' | sort -u); do
        if [ -n "${kernel}" ]; then
            echo "Generating initramfs for kernel version: ${kernel}"
            dracut --kver ${kernel} --force --add multipath --include /etc/multipath /etc/multipath --include /etc/multipath.conf /etc/multipath.conf || true
        fi
    done
else
    # Ubuntu with initramfs-tools
    if [ -f /etc/initramfs-tools/modules ]; then
        grep -q '^dm-multipath' /etc/initramfs-tools/modules || echo 'dm-multipath' >> /etc/initramfs-tools/modules
    fi
    update-initramfs -u -k all || update-initramfs -u
fi
update-grub
{{end}}
{{if eq .Dist "rhel"}}
subscription-manager unregister
subscription-manager clean
{{end}}
{{if or (eq .Dist "rhel") (eq .Dist "centos")}}
# Remove the ibm repositories used for the rsct installation
rpm -e ibm-power-repo-*.noarch
{{end}}

{{if eq .Dist "ubuntu"}}
if [ -f /etc/apt/sources.list.orig ]; then
    mv /etc/apt/sources.list.orig /etc/apt/sources.list
fi
if [ -d /etc/apt/sources.list.d.orig ]; then
    rm -rf /etc/apt/sources.list.d
    mv /etc/apt/sources.list.d.orig /etc/apt/sources.list.d
fi
{{end}}

if [ -e /etc/resolv.conf.orig ] || [ -L /etc/resolv.conf.orig ]; then
    rm -f /etc/resolv.conf
    mv /etc/resolv.conf.orig /etc/resolv.conf || true
fi
{{if or (eq .Dist "rhel") (eq .Dist "centos")}}
touch /.autorelabel
{{end}}
`

var CloudConfig = `# latest file from cloud-init-22.1-1.el8.noarch
users:
 - default

## Change 1: Enabling the root login
disable_root: 0
ssh_pwauth:   0

mount_default_fields: [~, ~, 'auto', 'defaults,nofail,x-systemd.requires=cloud-init.service', '0', '2']
resize_rootfs_tmp: /dev
ssh_deletekeys:   1
ssh_genkeytypes:  ['rsa', 'ecdsa', 'ed25519']
syslog_fix_perms: ~
disable_vmware_customization: false

cloud_init_modules:
 - disk_setup
 - migrator
 - bootcmd
 - write-files
 - growpart
 - resizefs
 - set_hostname
 - update_hostname
 - update_etc_hosts
 - rsyslog
 - users-groups
 - ssh

Set the default timezone to UTC:
timezone: UTC
cloud_config_modules:
 - mounts
 - locale
 - set-passwords
 - rh_subscription
 - yum-add-repo
 - package-update-upgrade-install
 - timezone
 - puppet
 - chef
 - salt-minion
 - mcollective
 - disable-ec2-metadata
 - runcmd

cloud_final_modules:
 - rightscale_userdata
 - scripts-per-once
 - scripts-per-boot
 - scripts-per-instance
 - scripts-user
 - ssh-authkey-fingerprints
 - keys-to-console
 - phone-home
 - final-message
 - power-state-change
 - reset_rmc

### Explicit steps for growing partitions, since
### growpart is failing on DM devices by default
### Ref: https://bugs.launchpad.net/cloud-init/+bug/1556260
write_files:
 - path: /tmp/update-disks.sh
   permissions: 0744
   owner: root
   content: |
      #!/usr/bin/env bash
      set -e
      for i in /dev/sd[a-z]; do
        partprobe $i || true
        part=$(partprobe -s $i | awk '{print $NF}')
        growpart $i $part || true
      done
      for i in /dev/mapper/mpath[a-z]; do
        partprobe $i || true
        part=$(partprobe -s $i | awk '{print $NF}')
        growpart $i $part || true
      done

runcmd:
 - bash /tmp/update-disks.sh
{{if eq .Dist "ubuntu"}}
 - resize2fs /dev/mapper/mpatha2 || resize2fs $(findmnt -n -o SOURCE /) || true
{{else}}
 - xfs_growfs -d /
{{end}}

### ^^^ Change 2: Recommendation from PowerVC

system_info:
  default_user:
    name: {{if eq .Dist "ubuntu"}}ubuntu{{else}}cloud-user{{end}}
    lock_passwd: true
    gecos: {{if eq .Dist "ubuntu"}}Ubuntu{{else}}Cloud User{{end}}
    groups: [adm, {{if eq .Dist "ubuntu"}}sudo{{else}}systemd-journal{{end}}]
    sudo: ["ALL=(ALL) NOPASSWD:ALL"]
    shell: /bin/bash
  distro: {{if eq .Dist "ubuntu"}}ubuntu{{else}}rhel{{end}}
  paths:
    cloud_dir: /var/lib/cloud
    templates_dir: /etc/cloud/templates
  ssh_svcname: {{if eq .Dist "ubuntu"}}ssh{{else}}sshd{{end}}

###############################################
### Change 3: Recommendation from PowerVC######
datasource_list: [ ConfigDrive, NoCloud, None ]
datasource:
  ConfigDrive:
    dsmode: local
###############################################

# vim:syntax=yaml
`

var dsIdentify = `policy: search,found=all,maybe=all,notfound=disabled
`

type Setup struct {
	Dist, RHNUser, RHNPassword, RootPasswd string
}

func Render(dist, rhnuser, rhnpasswd, rootpasswd string) (string, error) {
	s := Setup{
		dist, rhnuser, rhnpasswd, rootpasswd,
	}
	var wr bytes.Buffer
	t := template.Must(template.New("setup").Parse(SetupTemplate))
	err := t.Execute(&wr, s)
	if err != nil {
		return "", fmt.Errorf("error while rendering the script template: %v", err)
	}
	return wr.String(), nil
}

func RenderCloudConfig(dist string) (string, error) {
	s := Setup{
		Dist: dist,
	}
	var wr bytes.Buffer
	t := template.Must(template.New("cloud").Parse(CloudConfig))
	err := t.Execute(&wr, s)
	if err != nil {
		return "", fmt.Errorf("error while rendering the cloud config template: %v", err)
	}
	return wr.String(), nil
}
