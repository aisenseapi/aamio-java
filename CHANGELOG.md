# Changelog

Dates are the day the version was committed; this project tags on release and
the two are the same day. Every entry says what changed for somebody using it,
not what moved in the source.

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
