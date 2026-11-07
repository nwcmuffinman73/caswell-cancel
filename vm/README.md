# Render VM (UTM)

The rendering stage executes attacker JavaScript in a real browser engine. That never runs on the
Mac. It runs in this VM, which has no shared folders and no clipboard sharing. Work goes in as a
JSON worklist over SSH and comes back as files over rsync; the Mac stays the source of truth.

## Create the VM (one time, in UTM)
1. UTM → `+` → **Virtualize** → **Linux**.
2. Tick **Use Apple Virtualization**. Boot ISO: `ubuntu-26.10-snapshot1-live-server-arm64.iso`.
   (It is a daily snapshot. If the installer misbehaves, Ubuntu 24.04 LTS arm64 server is the safe fallback.)
3. Hardware: **4 CPU cores, 4096 MB RAM**. Storage: **40 GB**.
4. **Shared Directory: none.** Do not enable clipboard sharing. Network: default **Shared Network**.
5. Name it `cc-render`. Save, start, install Ubuntu Server:
   - user `cc`, any password (used once);
   - tick **Install OpenSSH server**; skip snaps.
6. After first boot, in the VM console: `ip -4 addr show | grep inet` → note the 192.168.64.x address.
7. On the Mac, once: `ssh-copy-id cc@<ip>` (type the password). Then tell Claude the IP.

Claude then runs `vm/setup-guest.sh` over SSH, which installs the render worker, and clones the VM
as `cc-render-clean` (Apple Virtualization has no snapshots) so it can be reverted after any suspicious run.

**Known issue (Ubuntu 26.10 snapshot, kernel 7.3 arm64):** Playwright's bundled Chromium and Firefox
segfault at launch. The worker uses Ubuntu's `snap install chromium` instead (`/snap/bin/chromium`),
which works. The guest also needs passwordless sudo for the VM user (`/etc/sudoers.d/<user>`), set once
from the VM console. Remove installer-added snaps you don't need (microk8s was present).

**Containment rule:** if a run looks like more than rendering (unexpected processes, outbound
connections beyond the browser, pegged CPU), hard-stop the VM — `utmctl stop Ubuntu26` — then revert:
`utmctl delete Ubuntu26 && utmctl clone cc-render-clean --name Ubuntu26`. Killing SSH alone contains nothing.

## Day to day
```sh
uv run cc render-push --limit 2000      # Mac: build worklist, rsync to VM, start worker
uv run cc render-pull                   # Mac: rsync results back, merge into snapshots
```
Revert the VM to `clean` any time: `utmctl stop cc-render && utmctl restore cc-render --snapshot clean` (or in the UTM UI).
