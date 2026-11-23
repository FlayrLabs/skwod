<!-- Security fix? Don't open a public pull request; see SECURITY.md first. -->

## What and why

<!-- What does this change, and what problem does it solve? Link the issue: "Fixes #123". -->

## Parts touched

- [ ] core
- [ ] server
- [ ] Apple apps
- [ ] Android app
- [ ] push gateway
- [ ] website
- [ ] host tray app
- [ ] docs / CI

## Verified

<!-- What you ran and what you couldn't run. "Built the Mac app, didn't run it on a device" is a fine answer. -->

- [ ] Tests for the parts I touched pass locally (commands in CONTRIBUTING.md).
- [ ] New behaviour has tests; a bug fix has a test that fails without it.
- [ ] Not verified, and why:

## Security-sensitive changes

<!-- Only if you touched crypto, keys, sessions, auth, push, sync trust, or the release/update code (see CODEOWNERS). -->

- What could an attacker in the threat model (docs/SECURITY.md) do with this change, and why can't they?
- Which failure cases are tested?

## Checklist

- [ ] Every commit is signed off (`git commit -s`, see CONTRIBUTING.md).
- [ ] No secrets, keys, personal data, real names or real invite links.
- [ ] No new dependency, or a reason for each one, pinned in the lockfile.
- [ ] I agree that this contribution is licensed under AGPL-3.0-only.
