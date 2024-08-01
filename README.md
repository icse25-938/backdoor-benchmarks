# Rosarum

This dataset is a collection of software infected with backdoors. Its purpose is to be used to
evaluate backdoor detection methods.

We distinguish between two types of target software:
- _Authentic_: real backdoors found in the wild
- _Synthetic_: artificial backdoors injected in (hopefully) backdoor-safe software (based on the
  [MAGMA](https://github.com/HexHive/magma) dataset)

For each target software, this dataset is able to produce three different versions:
- _Safe_: a backdoor-free version of the software (can be used to test the precision of a detection
  method)
- _Backdoored_: a version of the software containing a backdoor
- _Ground-truth_: the same as the _backdoored_ version, with the addition of a marker that can be
  used to verify whether the backdoor has been triggered


## How to build the backdoored software

You can either build all three versions (safe, backdoored, ground-truth) of a given target software
from the top-level Makefile:
```console
$ make sudo-1.9.15p5
```

Or you can build a specific version from the target's Makefile:
```console
$ cd synthetic/sudo-1.9.15p5/
$ make ground-truth
```


## Summary of target software and backdoors

| Name          | Type      | Target binary                        | Backdoor description                                                 | Reference                                                                                                                                                                   |
| ------------- | --------- | ------------------------------------ | -------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Belkin        | Authentic | `httpd`                              | HTTP request with secret URL value leads to web shell                | <https://conference.hitb.org/hitbsecconf2018dxb/materials/D1T1%20-%20Hunting%20for%20Backdoors%20in%20IoT%20Firmware%20at%20Unprecedented%20Scale%20-%20John%20Toterhi.pdf> |
| D-Link        | Authentic | `thttpd`                             | HTTP request with secret field value bypasses authentication         | <https://www.zdnet.com/article/d-link-routers-found-to-contain-backdoor/>                                                                                                   |
| Linksys       | Authentic | `scfgmgr`                            | Packet with specific payload enables memory read/write               | <https://github.com/elvanderb/TCP-32764/tree/master>                                                                                                                        |
| Tenda         | Authentic | `goahead`                            | Packet with specific payload enables command execution               | <https://web.archive.org/web/20131020145741/http://www.devttys0.com/2013/10/from-china-with-love>                                                                           |
| PHP (server)  | Authentic | `php`                                | HTTP request with secret field value enables command execution       | <https://doi.org/10.1145/3577923.3583657>                                                                                                                                   |
| ProFTPD       | Authentic | `proftpd`                            | Secret FTP command leads to root shell                               | <https://doi.org/10.1145/2508859.2516716>                                                                                                                                   |
| vsFTPd        | Authentic | `vsftpd`                             | FTP usernames containing `":)"` lead to root shell                   | <https://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html>                                                                                     |
| sudo          | Synthetic | `sudo`                               | Hardcoded credentials bypass authentication                          | N/A                                                                                                                                                                         |
| libpng        | Synthetic | `libpng_read_fuzzer`                 | Secret image metadata values enable command execution                | N/A                                                                                                                                                                         |
| libsndfile    | Synthetic | `sndfile_fuzzer`                     | Secret sound file metadata value triggers home directory encryption  | N/A                                                                                                                                                                         |
| libtiff       | Synthetic | `tiff_read_rgba_fuzzer`              | Secret image metadata value enables command execution                | N/A                                                                                                                                                                         |
| libxml2       | Synthetic | `libxml2_xml_reader_for_file_fuzzer` | Secret XML node format enables command execution                     | N/A                                                                                                                                                                         |
| Lua           | Synthetic | `lua`                                | Specific string values in script enable reading from filesystem      | N/A                                                                                                                                                                         |
| OpenSSL       | Synthetic | `bignum`                             | Secret bignum exponentiation string enables command execution        | N/A                                                                                                                                                                         |
| PHP (library) | Synthetic | `php-fuzz-unserialize`               | Specific string values in serialized object enable command execution | N/A                                                                                                                                                                         |
| Poppler       | Synthetic | `pdf_fuzzer`                         | Secret comment character in PDF enables command execution            | N/A                                                                                                                                                                         |
| SQLite3       | Synthetic | `sqlite3`                            | Secret SQL keyword enables removal of home directory                 | N/A                                                                                                                                                                         |
