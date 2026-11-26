Release notes
=============

Unreleased
----------

### New options

- `-replayvalidation=<mode>`: validation for replays of the block history. With
  `report`, the node runs every check it implements on each block it connects and logs
  each failure as one line, going on after a failure:

  ```
  replayvalidation: failure height=<height> block=<hash> check=<script|block-signature> tx=<txid|-> input=<index|-> error=<script error|->
  ```

  With `reject` a block with such a failure is also rejected
  (`replay-validation-failed`). A block rejected this way stays marked invalid in the
  block index when the node is later started without the option. `0` (the default)
  turns the mode off; any other value is an error at startup. The mode's checks store
  nothing in the signature or script caches.

- `-testactivationheight=name@height` (regtest only): sets the activation height of a consensus rule for tests.

### Other changes

- The hash calculation threads also hash the headers of block files during `-reindex`, `-loadblock` and the
  `bootstrap.dat` import.
- Regtest: the activation heights `newlogic` and `tokens` default to 0, and `-testactivationheight` accepts both
  names. A regtest node started without height options mines and accepts blocks. On regtest, setting `newlogic`
  both with `-testactivationheight` and with `-testnetNewLogicBlockNumber`, or `tokens` both with
  `-testactivationheight` and with `-tokenSupportBlockNumber`, is an error at startup.
- Regtest uses its own checkpoint data (its genesis block) and a token fee lock of 10 YAC for 10 blocks in
  every build. The checkpoints and the token fee lock mainnet uses are unchanged in both builds.
- Regtest uses its own stake-modifier checkpoint (one, at its genesis block) in every build. The stake-modifier
  checkpoints mainnet uses are unchanged in both builds.
- The help no longer lists `-detachdb`, `-btcyacprovider` and `-usdbtcprovider`. No code reads these options; a node
  started with them starts as before.
- `configure` looks only for `python3.6`, `python3.5`, `python3.4` and `python3` as the Python interpreter, no
  longer for `python2.7`, `python2` or `python`.
- Windows: the `modifier` field of `getblock` and `getblockbynumber` is 16 hex digits, and the 64-bit values in the
  `ComputeNextStakeModifier` and `CheckStakeKernelHash` debug-log lines and in the `-printcreation` reward lines
  print as their format says (hex after `0x`), without a trailing `64d`, `64u` or `64x`.
