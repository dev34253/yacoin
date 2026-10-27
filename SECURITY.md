# Security policy

This file explains how to report a vulnerability in YACoin privately, and what the maintainers do after a report.

## Supported versions

The YACoin network runs the releases of `yacoin/yacoin` (https://github.com/yacoin/yacoin/releases). `dev34253/yacoin` publishes no
releases of its own.

| Version | Supported |
|---|---|
| The latest release of `yacoin/yacoin` | yes |
| The `master` branch of `dev34253/yacoin` and of `yacoin/yacoin` | yes |
| Earlier releases | no |

If you run an earlier release, upgrade first and check whether the issue remains. If it affects only an earlier release that nodes on the
network still run, report it anyway, to `dev34253/yacoin` as in the second point below.

## Reporting a vulnerability

Never report a vulnerability in a public issue, pull request, discussion, commit or chat. Report it privately:

- **The issue is in the latest release of `yacoin/yacoin` (whether or not it is also in a `master` branch):** report it to
  `yacoin/yacoin` with GitHub's private vulnerability reporting. Open the Security tab of `yacoin/yacoin` and choose "Report a
  vulnerability". If `yacoin/yacoin` does not offer private reporting, report it to `dev34253/yacoin` instead, as in the next point.
- **The issue is not in any release (only in a `master` branch), or you are not sure:** report it to `dev34253/yacoin` with GitHub's
  private vulnerability reporting: https://github.com/dev34253/yacoin/security/advisories/new.

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

These are the steps for a report made to `dev34253/yacoin`. For a report made to `yacoin/yacoin`, its maintainers decide the steps, and
the maintainers of `dev34253/yacoin` help when asked.

There are no fixed response times. The project has few maintainers, and they handle each report as fast as they can. The steps are, in
order:

1. **Acknowledgement.** A maintainer acknowledges the report as soon as possible.
2. **Assessment.** The maintainers confirm the issue, find out which versions it affects and assess its severity. They tell you the
   result. If the issue is in a release, they add the `yacoin/yacoin` maintainers to the advisory and tell you. The discussion continues
   privately in the advisory.
3. **Fix in private.** The fix and a regression test are written in private, for example in the advisory's temporary private fork.
   Public commits and pull requests do not describe the vulnerability until the advisory is published.
4. **Coordinated release.** The maintainers pass the fix privately to the `yacoin/yacoin` maintainers and ask them to publish a fixed
   release without details in its release notes. Where possible, mining pools, exchanges and other node operators are told in advance to
   upgrade. A change to the consensus rules is coordinated with the miners as well.
5. **Publication.** The maintainers propose a disclosure date and agree it with you where possible. The advisory is published after the
   network has had time to upgrade. If no fixed release follows, the maintainers agree with you how and when to publish. The advisory
   credits you if you wish, and the maintainers can request a CVE for it.

For an issue that is in no release, steps 4 and 5 are shorter: the fix is merged to the `master` branch of `dev34253/yacoin` where that
branch has the issue, and offered to `yacoin/yacoin` before its next release. The advisory is published after the fix is merged and the
`yacoin/yacoin` maintainers have been told, on a date proposed as in step 5.

## Scope

In scope: the node `yacoind`, the wallet, `yacoin-cli`, `yacoin-qt`, consensus, P2P, RPC, and the build and release files in this
repository, for example `depends/`, `ci/`, `.github/` and the build scripts. A bug in a dependency (for example Boost, OpenSSL or
Berkeley DB) is in scope when it can be exploited through YACoin; otherwise report it to that dependency's own project.

Out of scope:

- third-party services, such as mining pools, exchanges and block explorers;
- attacks that need control of the user's machine;
- attacks that need an RPC interface that was deliberately exposed to untrusted networks.
