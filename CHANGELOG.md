# Changelog

Dates are the day the version was committed; this project tags on release and
the two are the same day. Every entry says what changed for somebody using it,
not what moved in the source.

## 0.3.1 - 2026-09-20

- `messages` missing, or of a type that is not a list, became an empty list before
  anything was checked, so a receipt saying "not-a-list" verified as a legitimate
  receipt for a thread nobody had written to: rootAddsUp, commitmentMatches and
  localHashesMatch all true. A field that is not there is not a field that is
  empty. A genuinely empty list still verifies.

## 0.3.0 - 2026-09-20

The minor moves because a returned field changed name, and because a check could
answer true without checking.

- `Check.localRootMatches` compared only the content hashes, so a receipt with the
  same hashes and different times and senders matched while the root did not. It is
  `localHashesMatch` now.
- Entries in `messages` were counted before they were filtered, so junk among them
  let the comparison run over the survivors and stop early -- and with every entry
  invalid the loop never ran at all and the answer was true, from no comparisons.
  A receipt this client cannot read whole is one it now says nothing true about.

## 0.2.7 - 2026-09-20

0.2.6 was tagged and never published: its `pom.xml` still said 0.2.5, so Maven
Central would have packaged it under the previous version, and the public
`Codec.VERSION` said 0.2.5 as well. A package that says two numbers about itself
is one nobody can report a bug against.

- Every place this package writes its own version says 0.2.7.
- `read` and `readThread` have overloads taking `limit` and `maxBytes`, which go
  out as `X-Limit` and `X-Max-Bytes`. The three- and four-argument forms are
  unchanged and ask for nothing.

## 0.2.6 - 2026-09-20

- `read` and `readThread` have overloads taking `limit` and `maxBytes`, which go out
  as `X-Limit` and `X-Max-Bytes`. A thread may hold two hundred messages of 65536
  bytes, so one read could be about a megabyte and there was no way to ask for less.
- The four- and three-argument forms are unchanged and ask for nothing.
- A smaller answer is not a looser one: `readThread` applies the same allowlist and
  still lists what it kept out.

## 0.2.5 - 2026-09-19

- a deeply nested body no longer overflows the stack, and the reply inbox is read with its list

## 0.2.4 - 2026-09-18

- read checks the hash and the signature itself, and readThread keeps the thread's own allowlist

## 0.2.3 - 2026-09-18

- work up to 32 bits within the time an inbox has, and a kept gate is asked again

## 0.2.2 - 2026-09-18

- replies hands over everything it read

## 0.2.0 - 2026-09-17

- scopes on the board
