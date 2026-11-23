# Reporting a security vulnerability

**Please do not open a public issue for a security problem.** Report it privately so that people
running Skwod can be given a fixed build before the details are public.

- Email: **security@skwod.io**
- Or use GitHub's private reporting: the **Report a vulnerability** button under this
  repository's *Security* tab.

If you want to encrypt your report, say so in a first message without details and we will arrange
a key.

## What to send

- What is affected: the server, the core, the iOS, macOS or Android app, the push gateway, the
  host tray app, or the release and update process — and the build number or commit.
- What an attacker can do, and what they need to be able to do it (a network position, a
  malicious server, a member account, physical access to a device).
- Steps to reproduce, or a proof of concept. A failing test against `core/` or `server/` is ideal.

## What to expect

- An acknowledgement within **3 working days**.
- An assessment, and a plan or an explanation of why we see it differently, within **14 days**.
- A fix as fast as the severity warrants. Skwod servers are run by their owners and apps update
  themselves at most once a day, so a fix takes time to reach everyone; we ask for **up to 90
  days** before public disclosure, and less when a fix has been out for a reasonable time.
- Credit in the release notes, unless you prefer otherwise.

This is a small project with no bug-bounty budget. We cannot pay for reports.

## Scope

In scope: everything in this repository, and the official builds made from it.

Especially interesting:

- anything that lets a server, its operator or a network attacker read message, attachment or
  call content, or obtain private keys;
- breaking the invariants listed under "Non-negotiable invariants" in
  [`docs/SECURITY.md`](docs/SECURITY.md);
- device linking, key backup and safety-number handling;
- the update path (forging or downgrading an update), the invite and join flow, the p2p
  transport and its loopback proxy, the host admin page;
- the push gateway learning more than the contract in [`docs/PUSH.md`](docs/PUSH.md) allows.

Known and documented, so not a new finding by itself: the items under "Remaining gaps versus
Signal" in [`docs/SECURITY.md`](docs/SECURITY.md) — for example that the server sees the social
graph and who posts in which channel. A way to make one of those gaps worse than described is
still in scope.

Vulnerabilities in **libsignal** itself belong with Signal (<https://support.signal.org/> →
security@signal.org); tell us too if Skwod's use of it is affected. The same goes for iroh,
LiveKit and other dependencies: report upstream, and let us know.

Out of scope: a Skwod server operated by someone else (talk to its operator), social engineering,
denial of service by sheer volume, and findings that need a rooted or jailbroken device or
malware already running as the user.

## Good faith

We will not pursue legal action against anyone who looks for vulnerabilities in good faith: who
tests only against their own server and accounts, does not read, change or destroy other people's
data, does not degrade a service others depend on, and gives us a reasonable time to fix a
problem before disclosing it.

## A note on what Skwod is

Skwod's protocol is Signal's libsignal, but Skwod's integration of it has **not been
independently audited**. If you are an auditor, [`docs/SECURITY.md`](docs/SECURITY.md) is the
place to start, and we would like to hear from you.
