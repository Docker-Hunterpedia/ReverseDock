# Bundled data

`common-passwords.txt`: passwords that dashboard users may not choose (ADR-0024). It is the
UK NCSC list of the 100,000 most used passwords from breach data, as published in
[SecLists](https://github.com/danielmiessler/SecLists/blob/1a7bb9127eca9e6ff2fc0301c597fe6e16a0cb56/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt)
(MIT licence, file last changed 2025-11-19, retrieved 2026-10-31), reduced to the entries a
user could choose at all: printable ASCII, 8 to 128 characters, lower-cased and de-duplicated
(46,453 lines, 441 KiB). Comparison ignores case.

Regenerate:

```sh
curl -sSfL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt \
  | LC_ALL=C tr -d '\r' | LC_ALL=C grep -v '[^ -~]' | LC_ALL=C tr 'A-Z' 'a-z' \
  | LC_ALL=C awk 'length($0)>=8 && length($0)<=128' | LC_ALL=C sort -u > common-passwords.txt
```
