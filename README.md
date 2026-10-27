# php-unserialize-sink-check

**Does request data reach `unserialize()` on this host?**

A read-only triage script for PHP object injection. It reports the PHP build, the plugin and theme
inventory with versions, and every `unserialize()` call site it can find — separating the files that also
read a request superglobal, because those are the ones where a request could plausibly reach a
deserialiser.

Written for a real question, kept because the question is general.

## Why this exists

PHP object injection needs two things at once: a serialised string an attacker controls, and a
`unserialize()` call that receives it. Security advisories usually talk about the first half — the payload
shape, the gadget chain, the memory bug it triggers — and leave the reader to work out whether anything on
their own host is even reachable.

That gap is where this tool sits. It was written while triaging a PHP engine bug (GH-24373, a use-after-free
when `serialize()` is called from a destructor during teardown) that was present in every release from 7.0
to 8.5.12. The engine bug is real, but it is worth nothing without an application-level path from a request
to `unserialize()`. Answering that for one WordPress site took an afternoon of reading vendor libraries;
the next host should not need the same afternoon.

Modern frameworks gate the obvious paths, so the interesting call sites are rarely in application code.
They are in `vendor/` libraries — queue and background-job packages that deserialise column values, admin
list tables, importers, option stores. Reading 4000 files by hand is not a realistic use of anyone's time.

## What it does

Everything here is read-only. No file is written, no code is executed from the scanned tree, no network
connection is opened, no shell is used. The only thing it changes is its own output.

- **PHP build** — version, SAPI, architecture, thread safety, `unserialize()` availability, loaded ini.
- **Relevant settings** — memory and POST limits, `session.serialize_handler`,
  `session.upload_progress.enabled`, `open_basedir`, `disable_functions`.
- **Target discovery** — walks up to five levels looking for `wp-config.php`, or scans a path you give it.
- **Inventory** — plugins and themes with versions, read from their own headers. WordPress is not
  bootstrapped, so no plugin code runs and no side effects occur.
- **`unserialize()` call sites** — counted, listed, and split into `unserialize()`, `maybe_unserialize()`,
  and calls wrapped in a decoder (`base64_decode`, `gzinflate`, `stripslashes`, `urldecode`, `hex2bin`).
- **Candidates** — files that both call `unserialize()` and read a superglobal. Reported separately,
  because co-occurrence in one file is a hint and not a finding.

Controls: symlinks are not followed, unreadable files are counted rather than silently skipped, the script
excludes itself, and the scan stops at `max_execution_time` minus a margin so a large tree cannot fatal the
request.

## Requirements

PHP 7.4 or newer, CLI or a web SAPI. Tested on 8.3.33 (CLI) and 8.4.27 (`fpm-fcgi`). No extensions beyond
the default set.

## Run it

### From the shell — preferred

```bash
php unserialize-sink-check.php --path=/var/www/html
```

No token, no exposure, nothing to clean up. If you omit `--path`, it looks for a WordPress install below the
current directory.

### Through the web — only if you have no shell

Set `$TOKEN` in the file to something random, upload it under a random name next to `wp-config.php`, request
it as `...?k=<token>`, and **delete it afterwards**.

An unedited copy refuses to run over HTTP. That is deliberate: the placeholder guard exists because drop-in
scripts that people forget to remove publish a plugin inventory, complete with versions, to anyone who
guesses the filename.

## Exit codes

| code | meaning |
| --- | --- |
| `0` | scanned, no file both calls `unserialize()` and reads a superglobal |
| `2` | scanned, at least one candidate — go read the files |
| `1` | usage error, or the token placeholder was not replaced |

`0` versus `2` makes it usable as a check rather than only as a report.

## Example output

Trimmed from a run against a synthetic tree containing one real sink and one database-only call site:

```
== unserialize-sink-check 1.0.0 ==============================
mode                               cli (no token needed)

== PHP build =================================================
PHP_VERSION                        8.3.33
PHP_SAPI                           cli
unserialize() available            true

== Target ====================================================
WordPress root                     not detected
scanning                           /srv/app

== unserialize() call sites ==================================
php files scanned                  2
scan completed                     yes
unserialize(                       1
maybe_unserialize(                 1
from decoded input                 1
files also reading superglobals    1

-- candidates: unserialize() AND a superglobal in the same file --
   /sink.php

   Co-occurrence is a heuristic, not a finding. Open each file and check whether
   the value handed to unserialize() is the one taken from the request.

-- every call site --
   /db.php    [maybe_unserialize(]
   /sink.php  [unserialize(]
   /sink.php  [from decoded input]
```

## What it cannot tell you

The pairing test is per file. It will not see a path where `a.php` reads `$_POST` and passes the value to a
function in `b.php` that deserialises it. Closing that needs data-flow analysis, not a grep.

So the two results mean different things:

- **No candidates** — no obvious sink. Useful, and the stronger of the two answers, but it is not an audit.
- **Candidates** — read the file. In the first run against a live WordPress host, four files were flagged
  and all four were false positives: an admin list table reads `$_GET` for sorting and separately
  deserialises database columns. Two unrelated code paths in one file.

A call site fed from the database is not a sink. A call site fed from `$_GET` is. Deciding which one you are
looking at requires opening the file — the tool's job is to tell you which four files out of four thousand.

## Use it only where you are authorised

The script reads configuration and source listing from the host it runs on. Run it on servers you own or
operate, or where you have written permission. Publishing the output is publishing your own inventory.

## Licence

MIT — see [LICENSE](./LICENSE). Copyright (c) 2026 GG ADVANCED IT Security UG.
