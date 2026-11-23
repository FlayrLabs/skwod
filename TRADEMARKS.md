# Skwod trademark policy

The Skwod source code is free software under the AGPL-3.0 ([`LICENSE`](LICENSE)). That licence
covers the code. It does **not** grant any right to the Skwod name or logo: like most free
software licences, it leaves trademarks out (and AGPL §7(e) lets a licensor decline to grant
them). This document says what you may do with the marks.

The aim is simple. When someone installs something called "Skwod", it should be the software the
Skwod project published — built from this source, signed with the project's keys. A messenger
that makes security promises cannot share its name with builds the project has never seen.

## The marks

"The marks" are, whether or not registered:

- the name **Skwod** (in any capitalisation, including "skwod" and "SKWOD"), and names confusingly
  similar to it;
- the **Skwod logo** (the squid mark) in every form;
- the **app icons**, menu-bar and tray icons, and launcher icons, including the image files in
  this repository under `apps/apple/Resources/Assets.xcassets/`, `apps/android/app/src/main/res/`
  (`mipmap-*`, `drawable/ic_launcher_foreground.png`) and `host/assets/`;
- the application identifiers `io.skwod.*` and `com.skwod.*`, the `skwod.io` domain, and the
  official update feeds and signing identities.

They belong to Flayr Labs LLC. The image files are in the repository so that the official apps
can be built from it; their presence is not a licence to use them on anything else.

## What you may do without asking

- **Run, study, modify and share the code** under the AGPL. Nothing here limits that.
- **Host a Skwod server** for yourself, your friends or your organisation, unmodified or
  modified, and call what you run "a Skwod server" or "our Skwod".
- **Build the apps from unmodified source for your own use**, with the name and icons as they
  are, on your own devices.
- **Say what your software is, truthfully**: "a fork of Skwod", "based on Skwod", "compatible
  with Skwod servers", "a client for Skwod". Use plain text, not the logo, and do not suggest the
  Skwod project made or endorses it.
- **Write about Skwod**: articles, reviews, tutorials, talks, packaging descriptions, including
  the logo where it illustrates the project itself.
- **Redistribute the official, unmodified binaries** as the project published them, saying where
  they came from.

## What needs a different name and different icons

If you **distribute a modified version** — to anyone beyond yourself, by any channel: an app
store, a website, a package repository, a sideloaded file — you must **rename and rebrand** it:

1. Give it a name that is not "Skwod" and could not be mistaken for it. "Skwod Plus", "OpenSkwod",
   "skwod-ng" and the like are not different names.
2. Replace the logo, the app icons, the menu-bar/tray icons and the launcher icons with your own.
3. Change the application identifiers (`PRODUCT_BUNDLE_IDENTIFIER`, `applicationId`, app group,
   keychain group) so your build does not present itself to the operating system as Skwod.
4. Point it at your own update feed and push gateway, with your own signing keys
   (`SKWOD_UPDATE_FEED`, `Updater.MANIFEST_URL`, `SUPublicEDKey`, `SKWOD_PUSH_GATEWAY`). A fork
   must not send its users to the official feeds or through the official gateway.
5. Keep the copyright and licence notices and the attribution the AGPL requires. Saying "based on
   Skwod" in your about screen and documentation is fine, and encouraged.

"Modified" means any change to the source that ends up in what you ship, including changed
defaults, added or removed features, and bundled extras. Building unmodified source with a
different compiler, or packaging it for a distribution without changing behaviour, is not a
modification — but such a build must still not be presented as an official one: say who built it.

The same applies to **unmodified builds you publish in an app store** under your own account:
stores present the publisher as the maker, so those need your own name and icons too.

## What you may not do

- Use the marks in the name of a product, company, domain, social account or app-store listing.
- Use the marks in a way that suggests the Skwod project or Flayr Labs LLC is affiliated with,
  sponsors or endorses you, your fork or your service.
- Sell merchandise with the marks.
- Alter the logo, or combine it with other marks.
- Present a build as official that the project did not sign.

## Asking

If you want to do something this policy does not allow, or are unsure, ask:
**hello@skwod.io**. Distribution packagers in particular are welcome to ask; the usual answer for
a faithful, clearly attributed package is yes.

This policy can change; the version in the repository is the current one. It is modelled on the
trademark policies of the Signal and Mozilla projects, and it is a statement of how the marks may
be used, not a contract or legal advice.

"Signal" is a trademark of Signal Messenger, LLC. Skwod is not affiliated with it.
