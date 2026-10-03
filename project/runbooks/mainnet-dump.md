# Runbook: per-block consensus value dump of mainnet (P0-08)

Produces the full dump of the mainnet chain with the hidden RPC
`dumpconsensusvalues` (format and columns: `src/test/README.md`,
"Consensus value dump"). The RPC runs inside `yacoind`, holds `cs_main` for
the whole run (about 7.5 minutes on the laptop, see the P0-08 Log) and is
read-only, but starting a node writes to its datadir. So it runs on a
**working copy** of a snapshot (runbook `mainnet-node-setup.md` §7), never
on the live node's datadir.

Commands are for the owner's laptop, where everything under `/srv/yacoin`
belongs to the `yacoin` user.

## 1. Binaries and working copy

Build the mainnet configuration (`contrib/testing/build.sh --config mainnet`)
and copy `yacoind` and `yacoin-cli` from `<builddir>/src/` to a directory
`yacoin` can read:

```bash
D=/srv/yacoin/dumps/p0-08
sudo -u yacoin mkdir -p $D
for b in yacoind yacoin-cli; do
  cat <builddir>/src/$b | sudo -u yacoin tee $D/$b >/dev/null
  sudo -u yacoin chmod 755 $D/$b
done
sudo -u yacoin cp -a /srv/yacoin/snapshots/<snapshot> $D/datadir
```

## 2. Configuration

`$D/datadir/yacoin.conf` (mode 600). The RPC needs a user and password;
pick a random password, it never leaves the machine:

```
server=1
rpcuser=p0dump
rpcpassword=<random>
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=17687
port=17688
listen=0
connect=0
dnsseed=0
disablewallet=1
persistmempool=0
rpcservertimeout=86400
checkblocks=1
```

`-txindex` and `-blockhashindex` are on by default and needed (without
the block-hash index every PoS row recomputes a scrypt hash; the RPC logs a
warning). No peers, no wallet, non-default ports (the live node uses 7687/7688), and
no `-debug` (with it every PoS kernel logs several lines). Even without it,
`GetNextTargetRequired` logs one "PoW constant target" line per post-fork
block (about 75,000 lines per full dump). Never use `-reindex-fast`.

## 3. Run

```bash
sudo -u yacoin $D/yacoind -datadir=$D/datadir -daemon
sudo -u yacoin $D/yacoin-cli -datadir=$D/datadir getblockcount   # wait until it answers
sudo -u yacoin $D/yacoin-cli -datadir=$D/datadir -rpcclienttimeout=86400 \
  dumpconsensusvalues $D/consensus-dump-<height>.csv
sudo -u yacoin $D/yacoin-cli -datadir=$D/datadir stop
```

`-rpcclienttimeout=0` does **not** disable the client timeout in this
version (libevent then uses its 50-second default; see
`project/known-issues.md`). If the client times out anyway, the RPC keeps
running in the node and finishes the file; its summary is in `debug.log`.

Progress is logged to `$D/datadir/debug.log` every 100,000 rows. Check
there that "Failed stake modifier checkpoint" does not appear (the
checkpoints are checked while the index is loaded) and that the summary
line's counters are 0 (except `required_bits_mismatch`, explained in the
format description). The RPC result has the same counters.

## 4. Store

```bash
cd /srv/yacoin/dumps
sudo -u yacoin zstd -19 -T4 --rm p0-08/consensus-dump-<height>.csv -o consensus-dump-<height>.csv.zst
sha256sum consensus-dump-<height>.csv.zst | sudo -u yacoin tee -a SHA256SUMS
```

Record rows, run time, compressed size, SHA-256, end height and hash in
the task Log. The full dump is not committed to git. The unit-test samples
in `src/test/data/` are ranges written by the RPC (node running, before
`stop`):

```bash
C="sudo -u yacoin $D/yacoin-cli -datadir=$D/datadir -rpcclienttimeout=86400"
$C dumpconsensusvalues $D/early.csv 1 60
$C dumpconsensusvalues $D/pos.csv 500040 500099
$C dumpconsensusvalues $D/fork.csv 1889990 1890010
```

Afterwards the working copy `$D/datadir` (about 2 GB) can be deleted.
