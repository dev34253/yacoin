# Runbook: mainnet node and self-hosted runner

Used by P0-07 (sync and snapshots), P0-24 (weekly reindex), P0-42 (soak) and
P0-44 (CI). Decisions behind it: `done/P0-00-phase0-decisions.md`.

## 1. Machine

| Resource | Minimum | Recommended | Why |
|---|---|---|---|
| OS | Linux x86-64 with Docker | Ubuntu 22.04 or 24.04 LTS | Builds run in the same container image as CI. |
| CPU | 4 cores | 8 cores | scrypt-jane header hashing during sync and reindex is CPU-bound. |
| RAM | 8 GB | 16 GB | Each scrypt-jane hash at N-factor 20–21 needs 256–512 MiB; plus `-dbcache`. |
| Disk | 500 GB SSD | 1 TB SSD | Live datadir + 2–3 snapshot copies + full dumps. Real chain size is measured in P0-07; adjust then. |
| Network | Outbound TCP 7688 | Also inbound 7688 | P2P. Inbound helps the network but is optional. |
| Uptime | – | Always on, UPS if possible | Weekly reindex takes 24–48 h. |

## 2. Base setup

```bash
# as an admin user
sudo apt update && sudo apt install -y git jq zstd
# Docker: install docker.io only if Docker is not already present
# (docker.io conflicts with Docker's own docker-ce packages)
command -v docker >/dev/null || sudo apt install -y docker.io
sudo adduser --disabled-password --gecos "" yacoin      # runs node and runner
sudo usermod -aG docker yacoin
sudo mkdir -p /srv/yacoin/{datadir,snapshots,dumps,bin} && sudo chown -R yacoin: /srv/yacoin
```

Firewall (if `ufw` is used): allow outbound 7688 (default allows all
outbound); optionally `sudo ufw allow 7688/tcp` for inbound. Keep the RPC port
7687 closed to the outside.

## 3. Build the mainnet binaries

Same image and `depends` approach as CI (Ubuntu 24.04 / GCC 11, `dev34253/yacoin-build:ubuntu.24.04-gcc11-1`, digest `sha256:d913fd15c3d4166f81a365e103486774414a8aa8bbc48b29448f92a013193a5b`, task P0-57); mainnet parameters (no
low-difficulty flag), no Qt.

Put the build steps in a script rather than one long nested `sudo -iu … bash -c "…"`
command – the nested quoting there broke the first real build (`CONFIG_SITE`
was never applied, so `configure` failed to find Berkeley DB even though
`depends` had built it).

```bash
sudo -iu yacoin
git clone https://github.com/dev34253/yacoin.git ~/yacoin
# Builds whatever is checked out (default: master). To build another ref:
#   git -C ~/yacoin fetch origin <ref> && git -C ~/yacoin checkout <ref>
cat > ~/build-mainnet.sh <<'EOS'
#!/bin/bash
set -euo pipefail
IMAGE="${IMAGE:-dev34253/yacoin-build:ubuntu.24.04-gcc11-1}"
cd "$HOME/yacoin"
docker run --rm -i --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$HOME/yacoin:/src" -w /src --entrypoint /bin/bash \
  "$IMAGE" -s <<'EOC'
set -euo pipefail
git config --global --add safe.directory /src
make -C depends -j"$(nproc)" HOST=x86_64-pc-linux-gnu NO_QT=1
./autogen.sh
CONFIG_SITE="$PWD/depends/x86_64-pc-linux-gnu/share/config.site" \
  ./configure --with-gui=no --enable-glibc-back-compat --enable-reduce-exports \
              LDFLAGS=-static-libstdc++ --prefix=/
make -j"$(nproc)"
EOC
git rev-parse HEAD > /srv/yacoin/bin/COMMIT
cp src/yacoind src/yacoin-cli /srv/yacoin/bin/
sha256sum /srv/yacoin/bin/yacoind /srv/yacoin/bin/yacoin-cli > /srv/yacoin/bin/SHA256SUMS
EOS
chmod +x ~/build-mainnet.sh && ~/build-mainnet.sh > ~/build.log 2>&1; tail -3 ~/build.log
```

Notes:
- The build needs a source tree with the glibc 2.36/2.38 fixes (any commit of
  this branch after `4b77e2c`). For older commits use
  `IMAGE=dev34253/yacoin-build:ubuntu.22.04-1 ~/build-mainnet.sh`.
- The `depends` step takes 20–40 minutes the first time; later builds reuse it.
- The version string ends in `-dirty`: `autogen.sh` rewrites some committed
  build-helper files. Harmless – no source files change.

Once P0-01 lands, replace the `docker run` block with
`contrib/testing/build.sh --config mainnet`.

## 4. Configure the node

`/srv/yacoin/datadir/yacoin.conf`:

```ini
server=1
daemon=0
# txindex is the default and required for PoS calculations
txindex=1
# MB; lower to 2000 on 8 GB machines
dbcache=4000
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcuser=yacoin
rpcpassword=CHANGE_ME_LONG_RANDOM
# set listen=0 if inbound 7688 is not open
listen=1
# known reliable peers in addition to the 7 built-in seeds:
#addnode=<ip>:7688
#addnode=<ip>:7688
```

Keep comments on their own lines – do not put `# …` after a value.
Generate a password with `openssl rand -hex 32`. Do not enable pruning.

## 5. Run as a service

`/etc/systemd/system/yacoind.service`:

```ini
[Unit]
Description=Yacoin mainnet node
After=network-online.target

[Service]
User=yacoin
ExecStart=/srv/yacoin/bin/yacoind -datadir=/srv/yacoin/datadir
ExecStop=/srv/yacoin/bin/yacoin-cli -datadir=/srv/yacoin/datadir stop
Restart=on-failure
TimeoutStopSec=600

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload && sudo systemctl enable --now yacoind
```

## 6. Monitor the sync

```bash
CLI="/srv/yacoin/bin/yacoin-cli -datadir=/srv/yacoin/datadir"
$CLI getconnectioncount          # should be > 0 within minutes
$CLI getpeerinfo | jq '.[].addr'
$CLI getblockcount               # rising – but see below
$CLI getinfo                     # overview (this version has no getblockchaininfo)
tail -f /srv/yacoin/datadir/debug.log
```

The node first downloads and checks all block headers (~2 million); `getblockcount`
stays flat during that stage (`debug.log` shows header batches). Header
verification slows down further along the chain because the scrypt-jane
N-factor rises (9 → 21). Expect hours for the full sync.

Not all built-in seeds are reachable (on 2026-10-02 96.32.210.58 timed out,
62.146.224.245 worked). Test one with
`timeout 6 bash -c 'echo > /dev/tcp/<ip>/7688' && echo open`. One reachable
peer is enough; the node discovers more from it.

If no peers connect: check outbound 7688, then add `addnode=` lines for
peers known from the community and restart.

Record in P0-07's Log: start/end time, final height and hash
(`getbestblockhash`), `du -sh` of `blocks/`, `chainstate/` and the datadir,
and peak memory (`systemctl status yacoind` or `ps -o rss`).

## 7. Snapshots (after the sync)

```bash
$CLI getblockcount; $CLI getbestblockhash         # record both before stopping
sudo systemctl stop yacoind
cd /srv/yacoin/datadir
tar -I 'zstd -T0' -cf /srv/yacoin/snapshots/mainnet-tip.tar.zst blocks chainstate
sha256sum /srv/yacoin/snapshots/mainnet-tip.tar.zst >> /srv/yacoin/snapshots/SHA256SUMS
sudo systemctl start yacoind
```

Height snapshots for P0-25 (e.g. just before/after the 1,890,000 hardfork):
copy `blocks/` into a fresh datadir and run
`yacoind -datadir=<copy> -reindex -stopatheight=<H>`, then archive as above.
Never use `-reindex-fast` for verification – it skips hash recomputation.

## 8. Register the self-hosted GitHub Actions runner

In GitHub: **dev34253/yacoin → Settings → Actions → Runners → New
self-hosted runner → Linux x64**. GitHub shows the current download URL and
a one-time token; run those commands as the `yacoin` user in
`~/actions-runner`, and at the configure step use:

```bash
./config.sh --url https://github.com/dev34253/yacoin --token <TOKEN> \
            --name yacoin-mainnet-1 --labels yacoin-mainnet --unattended
sudo ./svc.sh install yacoin && sudo ./svc.sh start
```

Security (important for a public repository): a self-hosted runner executes
workflow code on this machine.

- Settings → Actions → General → "Fork pull request workflows from outside
  collaborators": **Require approval for all outside collaborators**.
- Workflows that use `runs-on: [self-hosted, yacoin-mainnet]` must only
  trigger on `push` to protected branches, `schedule` and
  `workflow_dispatch` – never on `pull_request` (enforced in P0-44).
- The runner user has no sudo; the node's RPC is bound to localhost.

## 9. Hand-over checklist (tell Claude / record in P0-07)

- [ ] Machine specs (CPU, RAM, disk) and OS version
- [ ] Node synced: height, best block hash, sync duration, datadir size, peak memory
- [ ] Peer list used (`addnode` lines)
- [ ] Tip snapshot created with checksum
- [ ] Runner registered with label `yacoin-mainnet`, shows "Idle" in GitHub
- [ ] Fork PR approval setting enabled
