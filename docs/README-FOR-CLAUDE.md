# Standing Rules For This Project

These govern how work gets done here by default. They don't need to be re-litigated each
session — if something here doesn't fit this specific project, say so explicitly and update this
file, rather than silently deviating from it.

## No destructive actions without approval

Force-push, `git reset --hard`, `rm -rf`, dropping database tables, discarding uncommitted work —
none of these happen without being asked first, even when they'd be the fastest path past an
obstacle. If something is blocking progress, investigate the root cause rather than reaching for
a destructive shortcut.

## No auth-related DB writes without a heads-up first

Password hash resets, lockout clears, session/2FA state changes — flag these *before* acting,
not just disclose after the fact, even when the target is a local test/seed account. Same
category of caution as the destructive-actions rule, just lower stakes.

## Secret scans before every commit, not just the first one

Grep for key-shaped strings, tokens, and credentials in the actual diff before staging — every
time, not only when starting a new batch of work. A clean first commit doesn't guarantee a clean
fifth one.

## Separate, logically-grouped commits over squashed ones

Group by what changed and why, not by "everything I did this session." A security fix, a new
feature, and a docs update are three commits, not one — even in the same working session. Show
the grouping and the diffs before pushing, not after.

## Honest disclosure of partial or failed verification over silent substitution

If a test suite can't run, if a browser tool isn't connected, if a live check timed out — say so
plainly and explain what was actually verified instead. Never claim a stronger verification than
what actually happened (e.g. don't present "the code looks right" as "verified working").

## STOP gates at meaningful checkpoints, not racing to "done"

When a task has natural phase boundaries — a risky decision, a batch of commits ready to push, a
plan before a large build — pause there and confirm before continuing, especially when
explicitly asked to. "I could keep going" is not the same as "I should keep going without
checking in."

---


## When something looks flaky, verify empirically before assuming

Reproduce locally, check load/timing, look at what actually changed — don't hand-wave a failure
away as "probably flaky" without evidence, and don't assume a fix worked without re-running it.

---

## Project-specific notes (D:\ovpn)

- No CI and no test suite: this project is PowerShell scripts plus data. "Verification" means
  real measurements with timestamps, and saying plainly what wasn't measured.
- Report-only: no pfSense/firewall/router configs, no paid signups (decisions.md ADR-001).
- Never store or print NordVPN service credentials or private keys. The `.ovpn` files contain
  NordVPN's public CA plus a shared tls-auth key, so keep them out of any public repo.
- Target shell is Windows PowerShell 5.1 (no `&&`, `??`, `?.`).
