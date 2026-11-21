# FlawRook agent

The FlawRook agent lists a Linux server's OS packages and runtimes, and sends the list to
FlawRook. FlawRook matches it against vulnerability data. The agent runs as a systemd service.

## What it does on your host

**It reads, and writes almost nothing.**
- It reads:
  - the package databases: dpkg, rpm and apk;
  - `/etc/os-release`;
  - the running kernel's version (`uname -r`);
  - the hostname;
  - `/etc/machine-id`, only to derive a one-way host ID;
  - the mount table, to skip network mounts;
  - its settings in `/etc/flawrook/agent.yaml`;
  - the runtime binaries it identifies by their version strings (Node.js, Python, PHP, nginx, Redis and the like).
- It writes nothing outside `/var/lib/flawrook`. That directory gets one file, `host-id`, and only on a host without a machine ID.
- It doesn't walk `/proc`, `/sys`, `/dev`, `/run`, `/tmp`, container storage, or network and FUSE mounts (NFS, SMB, sshfs), unless `include_mounts` names them.
- The service runs as a user of its own (systemd `DynamicUser`) with one capability, `CAP_DAC_READ_SEARCH`, which lets it read any file and grants nothing else. It can't write elsewhere: `ProtectSystem=strict` and `ProtectHome=read-only`.

**Memory.**
- Go's heap is held to 96 MiB (`GOMEMLIMIT`), and the whole process is capped at 256 MB (`MemoryMax=256M`).
- The measured peak is 108 to 149 MB, on Debian 12 and 13, Ubuntu 24.04, Alpine 3.20 and Rocky Linux 9 test hosts and on runtime images (Node.js, Python, PHP, Redis, nginx, Go). The binary itself is a large part of that.
- A scan took under 4 seconds on those hosts.
- Large application trees don't add to it, since it doesn't walk them. On a test host with 310,000 files of `node_modules`, web roots and a kernel source tree, a scan took 0.9 seconds and peaked at 136 MB. Version 0.1.0 walked every directory: there it needed 74 seconds and 365 MB, and the unit's 256 MB cap stopped it.
- Each scan logs one line, such as `scan 0.9 s, 108 packages, peak 136 MiB`: `journalctl -u flawrook-agent`.

**CPU and disk priority.**
- The scan yields to everything else: CPU at the lowest priority (`Nice=19`) and disk reads at the lowest best-effort level (`IOSchedulingClass=best-effort`, `IOSchedulingPriority=7`).
- It isn't the idle IO class, which can starve a scan on a disk that is never idle.
- Run by hand, the agent lowers its own priority to the same levels before it scans. If the system refuses, it says so and runs at normal priority.

**Network.**
- It makes outbound connections only, and only to the FlawRook address you configure (`url`), over HTTPS. It looks up only that host's name, or the proxy's if you set one (`https_proxy`).
- It opens no port (`SocketBindDeny=any`) and takes no commands.
- It doesn't follow redirects.
- There's no update check, no telemetry, and no other host.
- `test/network-proof.sh` shows this. It runs the agent on a network with no route out, traces every `connect()` with strace, and captures every packet with tcpdump. A dry run makes no connection. A real run reaches only the configured host and looks up only that name.

**What it sends, and when.**
- It sends:
  - the package list (a CycloneDX SBOM: names, versions, where they were found);
  - the os-release fields;
  - the hostname;
  - the kernel version;
  - the host ID;
  - its own version.
- It never sends file contents.
- It checks once an hour, and sends the full list only when FlawRook doesn't have it:
  - the first time;
  - when the list changed. A new agent version counts as a change: a newer version may catalog the host differently, so after an upgrade FlawRook gets a fresh list;
  - when FlawRook asks for it.
- Otherwise the hourly check (a heartbeat) only says the server is still there.
- After a restart or a settings reload, the first check is a heartbeat too. Restarting many servers at once doesn't send their lists again.

**See it before it sends anything.** `flawrook-agent --dry-run` prints the exact report it would send and sends nothing.

**Stop it or remove it.**
- Stop: `sudo systemctl stop flawrook-agent`. Stop it for good: `sudo systemctl disable --now flawrook-agent`.
- Remove:
  - deb: `sudo apt remove flawrook-agent`. `apt purge` also removes `agent.yaml`; an `agent.yaml.bak` left by a token change stays in `/etc/flawrook`;
  - rpm: `sudo dnf remove flawrook-agent`;
  - a plain binary install: `sudo systemctl disable --now flawrook-agent`, then remove `/usr/local/bin/flawrook-agent`, `/etc/systemd/system/flawrook-agent.service` and `/etc/flawrook`, and run `sudo systemctl daemon-reload`.
- What's left in any case: `/var/lib/flawrook`, which holds the generated host ID. Under systemd's `DynamicUser` it lives in `/var/lib/private/flawrook`.
- Then revoke its token in FlawRook, under Integrations, Agents.

## Install

One line, with the address and token from FlawRook (Integrations, Agents):

    curl -fsSL https://github.com/flawrook/agent/releases/latest/download/install.sh | sudo env FLAWROOK_URL=<your FlawRook address> FLAWROOK_TOKEN=flra_… sh

Or in two steps, which keeps the token out of your shell history:
1. Write `url` and `token` to `/etc/flawrook/agent.yaml` (mode 0600).
2. Run `install.sh` without `FLAWROOK_TOKEN`.

`install.sh` checks every file it downloads against the release's `checksums.txt`. It writes the token only to `agent.yaml`, never into the service unit. It starts the service only once a token is set.

It needs systemd 235 or newer: Debian 10, Ubuntu 18.04, RHEL, Rocky Linux and AlmaLinux 8, or later. An older systemd ignores `DynamicUser`, and the agent would run as root. So on an older systemd, or one whose version it can't read, `install.sh` stops before it installs anything. The deb or rpm installed by itself puts its files in place, but neither enables nor starts the service, and says why. If an older systemd starts it all the same (a unit enabled by hand), the agent sees it runs as root under systemd, logs why and stops with exit status 78, which the unit doesn't restart. A root shell that inherits systemd's `INVOCATION_ID` (`systemd-run --shell`, or `su` without `-` inside a systemd user unit) is refused the same way: run the agent there with `env -u INVOCATION_ID flawrook-agent`. Alpine and other systems without systemd have no such floor.

## Settings

`/etc/flawrook/agent.yaml`. A flag wins over the environment, which wins over this file. A misspelt key stops the agent at start.

| Key | Environment | Meaning |
|---|---|---|
| `url` | `FLAWROOK_URL` | Your FlawRook address. https, or plain http only to localhost |
| `token` | `FLAWROOK_TOKEN` | The agent token |
| `hostname` | `FLAWROOK_HOSTNAME` | Reported instead of the real hostname |
| `ca_file` | `FLAWROOK_CA_FILE` | A PEM bundle trusted besides the system's |
| `https_proxy`, `no_proxy` | `HTTPS_PROXY`, `NO_PROXY` | A proxy for the connection to FlawRook |
| `include_mounts` | `FLAWROOK_INCLUDE_MOUNTS` | Network or FUSE mount points to walk anyway (absolute paths) |

`sudo systemctl reload flawrook-agent` rereads the file.

## Licence

Apache-2.0, see `LICENSE` and `NOTICE`. The licence files of the modules it's built with are in `third_party/licenses`.
