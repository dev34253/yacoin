Test Shell for Interactive Environments
=========================================

This document describes how to use the `TestShell` submodule in the functional
test suite.

The `TestShell` submodule extends the `BitcoinTestFramework` functionality to
external interactive environments for prototyping and educational purposes. Just
like `BitcoinTestFramework`, the `TestShell` allows the user to:

* Manage regtest yacoind subprocesses.
* Access RPC interfaces of the underlying yacoind instances.
* Log events to the functional test logging utility.

The `TestShell` can be useful in interactive environments where it is necessary
to extend the object lifetime of the underlying `BitcoinTestFramework` between
user inputs. Such environments include the Python3 command line interpreter or
[Jupyter](https://jupyter.org/) notebooks running a Python3 kernel.

## 1. Requirements

* Python3
* `yacoind` built in this repository.
* The test framework's config file. A configure in the source tree writes it
  as `test/config.ini`, the default. With `./dev.sh build dev` it is
  `/path/to/yacoin/build/dev/test/config.ini`: pass it to `setup()` as
  `configfile="/path/to/yacoin/build/dev/test/config.ini"`. The environment
  variables `BITCOIND` and `BITCOINCLI` name other `yacoind` and `yacoin-cli`
  binaries than those of the config file's build directory.

## 2. Importing `TestShell` from this repository

We can import the `TestShell` by adding the path of this repository's
`test_framework` module to the beginning of `sys.path`, and then
importing the `TestShell` class from the `test_shell` sub-package.

```
>>> import sys
>>> sys.path.insert(0, "/path/to/yacoin/test/functional")
>>> from test_framework.test_shell import TestShell
```

The following `TestShell` methods manage the lifetime of the underlying yacoind
processes and logging utilities.

* `TestShell.setup()`
* `TestShell.shutdown()`

The `TestShell` inherits all `BitcoinTestFramework` members and methods, such
as:
* `TestShell.nodes[index].rpc_method()`
* `TestShell.log.info("Custom log message")`

The following sections demonstrate how to initialize, run, and shut down a
`TestShell` object.

## 3. Initializing a `TestShell` object

```
>>> test = TestShell().setup(num_nodes=2, setup_clean_chain=True)
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework (INFO): Initializing test directory /path/to/bitcoin_func_test_XXXXXXXX
```
The `TestShell` forwards all functional test parameters of the parent
`BitcoinTestFramework` object. The main argument keywords which can be used to
initialize the `TestShell` are listed in [section
#6](#6-custom-testshell-parameters) of this document.

**Note: Running multiple instances of `TestShell` is not allowed.** Running a
single process also ensures that logging remains consolidated in the same
temporary folder. If you need more yacoind nodes than set by default (1),
simply increase the `num_nodes` parameter during setup.

```
>>> test2 = TestShell().setup()
TestShell is already running!
```

## 4. Interacting with the `TestShell`

Unlike the `BitcoinTestFramework` class, the `TestShell` keeps the underlying
yacoind subprocesses (nodes) and logging utilities running until the user
explicitly shuts down the `TestShell` object.

During the time between the `setup` and `shutdown` calls, all `yacoind` node
processes and `BitcoinTestFramework` convenience methods can be accessed
interactively.

**Example: Mining a regtest chain**

With `setup_clean_chain=True`, the `TestShell` nodes are initialized with a
clean chain. This means that each node of the `TestShell` is initialized with
a block height of 0.

```
>>> test.nodes[0].getblockcount()
0
```

We now let the first node generate 10 regtest blocks, and direct the coinbase
rewards to a wallet address owned by the mining node.

```
>>> address = test.nodes[0].getnewaddress()
>>> test.nodes[0].generatetoaddress(10, address)
['16ca8bd20221aab103baf49a280fffc05e1976a4c1e11d8ed0929e9fe5df8fcd', ...
```
During `setup`, the second node opens an outbound connection to the first, so
the mined blocks propagate to it. `test.sync_all()` waits until both nodes have
the same blocks and mempool.

```
>>> test.sync_all()
>>> test.nodes[1].getblockcount()
10
```
The rewards of the blocks that have reached coinbase maturity are now
spendable by the wallet of the first node.

```
>>> test.nodes[0].getbalance()
Decimal('19.012850')
```

We can also log custom events to the logger.

```
>>> test.nodes[0].log.info("Successfully mined regtest chain!")
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework.node0 (INFO): Successfully mined regtest chain!
```

**Note: Please also consider the description of the functional tests in
[developer-build.md](../../doc/developer-build.md#functional-tests)**. Modules
such as [key.py](test_framework/key.py),
[script.py](test_framework/script.py) and
[messages.py](test_framework/messages.py) are particularly
useful in constructing objects which can be passed to the yacoind nodes managed
by a running `TestShell` object.

## 5. Shutting the `TestShell` down

Shutting down the `TestShell` will safely tear down all running yacoind
instances and remove all temporary data and logging directories.

```
>>> test.shutdown()
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework (INFO): Stopping nodes
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework (INFO): Cleaning up /path/to/bitcoin_func_test_XXXXXXXX on exit
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework (INFO): Tests successful
```
To keep the logs and data directories instead, set the
`TestShell.options.nocleanup` member of a running `TestShell` to `True` before
calling `shutdown`:
```
>>> test.options.nocleanup = True
>>> test.shutdown()
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework (INFO): Stopping nodes
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework (WARNING): Not cleaning up dir /path/to/bitcoin_func_test_XXXXXXXX
20XX-XX-XXTXX:XX:XX.XXXXXXZ TestFramework (INFO): Tests successful
```

The following utility consolidates logs from the yacoind nodes and the
underlying `BitcoinTestFramework`:

* `/path/to/yacoin/test/functional/combine_logs.py
  '/path/to/bitcoin_func_test_XXXXXXXX'`

## 6. Custom `TestShell` parameters

The `TestShell` object initializes with the default settings inherited from the
`BitcoinTestFramework` class. The user can override these in
`TestShell.setup(key=value)`.

**Note:** `TestShell.reset()` will reset test parameters to default values and
can be called after the TestShell is shut down.

| Test parameter key | Default Value | Description |
|---|---|---|
| `bind_to_localhost_only` | `True` | Adds `bind=127.0.0.1` to the nodes' `yacoin.conf` if set to `True`, so they listen for peers on `127.0.0.1` only. |
| `cachedir` | `"/path/to/yacoin/test/cache"` | Sets the directory of the cached block chains the nodes start from when `setup_clean_chain` is `False`. |
| `chain`  | `"regtest"` | Sets the chain-type for the underlying test yacoind processes: `"main"` or `"regtest"`. |
| `configfile` | `"/path/to/yacoin/test/config.ini"` | Sets the location of the test framework config file. |
| `coveragedir` | `None` | Records yacoind RPC test coverage into this directory if set. |
| `loglevel` | `INFO` | Logs events at this level and higher to the console; `test_framework.log` in the test directory gets all levels. Can be set to `DEBUG`, `INFO`, `WARNING`, `ERROR` or `CRITICAL`. |
| `nocleanup` | `False` | Keeps the temporary test directory after `shutdown` if set to `True`. |
| `noshutdown` | `False` | Does not stop the yacoind instances at `shutdown` if set to `True`; the test directory is kept as well. |
| `num_nodes` | `1` | Sets the number of initialized yacoind processes. |
| `perf` | `False` | Profiles running nodes with `perf` for the duration of the test if set to `True`. |
| `rpc_timeout` | `600` | Sets how many seconds the framework waits for a node's RPC server to start and to reply. |
| `setup_clean_chain` | `False` | Starts the nodes from a copy of the cached 40-block chain, on which the first node mines one more block. Each node starts with only the genesis block (block height 0) if set to `True`. |
| `randomseed` | `None` | Seeds Python's `random` module at `setup`; if not set, `setup` draws a random seed and logs it at `DEBUG` (`PRNG seed is: ...`). Set a constant for reproducible test runs. |
| `supports_cli` | `True` | Whether the test supports `usecli`; with `usecli` set and `supports_cli` `False`, `setup` raises `SkipTest`. |
| `tmpdir` | `None` | Sets the test directory for the logs and the nodes' data directories, which must not exist yet. If not set, a new `bitcoin_func_test_XXXXXXXX` directory in the system's temporary directory. `shutdown` deletes it after a successful test run unless `nocleanup`, `noshutdown` or `perf` is set to `True`. |
| `trace_rpc` | `False` | Logs all RPC calls if set to `True`. |
| `usecli` | `False` | Uses the yacoin-cli interface for all yacoind commands instead of directly calling the RPC server. Requires `supports_cli`. |
