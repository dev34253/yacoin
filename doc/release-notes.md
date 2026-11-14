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
