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

package mounts

import (
	"reflect"
	"testing"
)

// A host's mount table: the root and /boot on local disks, the pseudo filesystems, an NFS share, an
// sshfs mount, an SMB share with a space in its path, and an NFS mount the admin wants walked.
const table = `22 1 259:2 / / rw,relatime shared:1 - ext4 /dev/nvme0n1p2 rw
23 22 0:21 / /proc rw,nosuid shared:12 - proc proc rw
24 22 0:22 / /sys rw,nosuid shared:2 - sysfs sysfs rw
25 22 259:1 / /boot rw,relatime shared:28 - vfat /dev/nvme0n1p1 rw
40 22 0:45 / /mnt/nfs rw,relatime shared:30 - nfs4 fileserver:/export rw,vers=4.2
41 22 0:46 / /home/ops/remote rw,nosuid shared:31 - fuse.sshfs ops@backup:/data rw,user_id=1000
42 22 0:47 / /mnt/team\040share rw,relatime shared:32 - cifs //nas/team rw,vers=3.1.1
43 22 0:48 / /srv/data rw,relatime shared:33 - nfs nas:/data rw,vers=3
44 22 0:49 / /var/lib/ntfs rw,relatime shared:34 - fuseblk /dev/sdb1 rw
not a mountinfo line
`

func TestParse(t *testing.T) {
	got := Parse(table)
	want := []Mount{
		{"/", "ext4"}, {"/proc", "proc"}, {"/sys", "sysfs"}, {"/boot", "vfat"},
		{"/mnt/nfs", "nfs4"}, {"/home/ops/remote", "fuse.sshfs"}, {"/mnt/team share", "cifs"},
		{"/srv/data", "nfs"}, {"/var/lib/ntfs", "fuseblk"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
}

func TestNetworkAndFUSEMountsAreSkippedUnlessIncluded(t *testing.T) {
	got := Skipped(Parse(table), []string{"/srv/data/"})
	// /srv/data is NFS but listed in include_mounts; fuseblk is a local disk (NTFS), not fuse.*.
	want := []string{"/mnt/nfs", "/home/ops/remote", "/mnt/team share"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
	if all := Skipped(Parse(table), nil); len(all) != 4 || all[3] != "/srv/data" {
		t.Fatalf("without include_mounts: %q", all)
	}
	for _, typ := range []string{"nfs", "nfs4", "cifs", "smb3", "fuse.sshfs", "fuse.rclone", "fuse.s3fs"} {
		if !skippedType(typ) {
			t.Errorf("%s isn't skipped", typ)
		}
	}
	for _, typ := range []string{"ext4", "xfs", "btrfs", "overlay", "tmpfs", "fuseblk", "fuse", "nfsd", "vfat"} {
		if skippedType(typ) {
			t.Errorf("%s is skipped", typ)
		}
	}
}

func TestTheRootIsNeverSkipped(t *testing.T) {
	if got := Skipped([]Mount{{"/", "nfs"}, {"/data", "nfs"}}, nil); !reflect.DeepEqual(got, []string{"/data"}) {
		t.Fatalf("a diskless host: %q", got)
	}
}

func TestPatternsAreRootRelativeAndEscaped(t *testing.T) {
	got := Patterns([]string{"/mnt/nfs", "/mnt/team share", "/mnt/odd[1]*?{x}"})
	want := []string{"./mnt/nfs/**", "./mnt/team share/**", `./mnt/odd\[1\]\*\?\{x\}/**`}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %q", got)
	}
}
