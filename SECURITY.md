# Security policy

This file explains how to report a vulnerability in YACoin privately, and what the maintainers do after a report.

## Supported versions

The YACoin network runs the releases of `yacoin/yacoin` (https://github.com/yacoin/yacoin/releases). The latest release is `v1.11.0`. This
repository publishes no releases of its own.

| Version | Supported |
|---|---|
| The latest release of `yacoin/yacoin` (`v1.11.0`) | yes |
| The `master` branch of this repository | yes |
| Earlier releases | no |

If you run an earlier release, upgrade first and check whether the issue remains.

## Reporting a vulnerability

Never report a vulnerability in a public issue, pull request, discussion, commit or chat. Report it privately:

- **The issue is in a released version, and so affects the running network:** report it to `yacoin/yacoin` with GitHub's private
  vulnerability reporting. Open the Security tab of `yacoin/yacoin` and choose "Report a vulnerability". If `yacoin/yacoin` does not offer
  private reporting, report it here instead. The maintainers here then pass it on privately to the `yacoin/yacoin` maintainers.
- **The issue is only in the `master` branch of this repository, or you are not sure:** report it here with GitHub's private
  vulnerability reporting: https://github.com/dev34253/yacoin/security/advisories/new.

GitHub's private vulnerability reporting is the only channel. There is no security email address and no OpenPGP key.

Please include:

- the affected version or commit;
- the component, for example P2P, RPC, wallet, consensus or block validation, mining, or the build and release files;
- steps to reproduce, or a proof of concept;
- the impact;
- whether you know of it being used on the network;
- whether you want to be credited, and how.

There is no bug bounty.

## What happens after a report

There are no fixed response times. The project has few maintainers, and they handle each report as fast as they can. The steps are, in
order:

1. **Acknowledgement.** A maintainer acknowledges the report as soon as possible.
2. **Assessment.** The maintainers confirm the issue, find out which versions it affects and assess its severity. They tell you the
   result. The discussion continues privately in the advisory.
3. **Fix in private.** The fix and a regression test are written in the advisory's temporary private fork, or in another private branch.
   Public commits and pull requests say nothing about it.
4. **Coordinated release.** Before any details become public, the `yacoin/yacoin` maintainers, mining pools, exchanges and other node
   operators receive the fixed release and time to upgrade. A change to the consensus rules is coordinated with the miners as well.
5. **Publication.** The disclosure date is agreed with you. The advisory is published after the network has had time to upgrade. It
   credits you if you wish, and it can get a CVE.

## Scope

In scope: the node `yacoind`, the wallet, `yacoin-cli`, `yacoin-qt`, consensus, P2P, RPC, and the build and release files in this
repository (`depends/`, `ci/`, `.github/`).

Out of scope:

- third-party services, such as mining pools, exchanges and block explorers;
- attacks that need control of the user's machine;
- attacks that need an RPC interface that was deliberately exposed to untrusted networks.
