Task: `<id>`

## What changed

<!-- What and why, in a few lines. Name the MG rows; do not describe security findings (this repository is public). -->

## How it was tested

<!-- Commands run, new or changed tests, and the link to the green CI run. -->

## Acceptance criteria

<!-- Copy from the task file and tick each one with its evidence. -->
- [ ]

## Checks

- Product code changed (compiled into `yacoind`, `yacoin-cli`, `yacoin-qt`): yes / no
- Consensus-critical: no / neutral / rule change
  <!-- neutral: the argument why no block changes validity, or the replay result over mainnet; rule change: the activation -->
- Verifier report (consensus-critical only): <!-- link or "n/a" -->
- `known_failure` markers removed: <!-- list or "none" -->
- New or upgraded dependency: no / yes (upstream signature or hash checked)
- Removes a user-visible feature, option or RPC: no / yes (decision record and release note linked)
- Documents in the planning repository that this change makes wrong: none / updated in the same task (list them)
- Owner approval needed: yes / no
- Independent review: <!-- verdict, and how each finding was answered -->
