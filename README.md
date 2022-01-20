## Rust-Security

Rust Language Security


execrices: [rust-ctf](https://github.com/xxg1413/rust-ctf)

## CVE

## Rust-lang

| ID | RUSTSEC-ID | CVE-ID  |    Description    |  Writeup |
|:--:| :--------  | :--------|    :-----------:  |  :----------:  |
|  | [RUSTSEC-2022-0001](https://rustsec.org/advisories/RUSTSEC-2022-0001.html) | [CVE-2022-21658](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21658) | `std::fs::remove_dir_all`standard library function is vulneable a race condition enabling symlink following (CWE-363). |  |
|  | [RUSTSEC-2021-0001](https://rustsec.org/advisories/RUSTSEC-2021-0001.html) | [CVE-2020-26297](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-26297) | XSS in mdBook's search page | [mdBook搜索界面的XSS](./CVE-2020-26297) |
|  | | [CVE-2019-1010299](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-1010299) | Obtain Information | None |
|  | | [CVE-2019-16760](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16760) | Cargo download the wrong dependency | None |
|  | | [CVE-2019-12083](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12083) | IOverflow  | None |
|  | | [CVE-2018-1000810](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000810) | Integer Overflow to Buffer Overflow  | None |
|  | | [CVE-2018-1000657](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000657) | Buffer Overflow | None |
|  | | [CVE-2018-1000622](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000622) | Uncontrolled Search Path Element | None |
| 14 |  | [CVE-2017-20004](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-20004)  | MutexGuard<Cell<i32>> must not be Sync | None |
| 13 | [RUSTSEC-2017-0007](https://rustsec.org/advisories/RUSTSEC-2017-0007.html) |   | lz4-compress is unmaintained | None |
| 12 | [RUSTSEC-2017-0006](https://rustsec.org/advisories/RUSTSEC-2017-0006.html) |    | Unchecked vector pre-allocation | None |
| 11 | [RUSTSEC-2017-0005](https://rustsec.org/advisories/RUSTSEC-2017-0005.html) | [CVE-2017-18589](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18589) | Large cookie Max-Age values can cause a denial of service | None |
| 10 | [RUSTSEC-2017-0004](https://rustsec.org/advisories/RUSTSEC-2017-0004.html) |  [CVE-2017-1000430](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000430)  |  Integer overflow leads to heap-based buffer overflow in encode_config_buf | None |
| 9 | [RUSTSEC-2017-0003](https://rustsec.org/advisories/RUSTSEC-2017-0003.html) |  [CVE-2017-18588](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18588)  |  Hostname verification skipped when custom root certs used | None |
| 8 | [RUSTSEC-2017-0002](https://rustsec.org/advisories/RUSTSEC-2017-0002.html) | [CVE-2017-18587](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-18587)  | headers containing newline characters can split messages | None |
| 7 | [RUSTSEC-2017-0001](https://rustsec.org/advisories/RUSTSEC-2017-0001.html) | [CVE-2017-10001683](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-10001683) | scalarmult() vulnerable to degenerate public keys | None |
| 6 | [RUSTSEC-2016-0006](https://rustsec.org/advisories/RUSTSEC-2016-0006.html) |  | cassandra crate is unmaintained; use cassandra-cpp instead | None |
| 5 | [RUSTSEC-2016-0005](https://rustsec.org/advisories/RUSTSEC-2016-0005.html) |  | rust-crypto is unmaintained; switch to a modern alternative | None |
| 4 | [RUSTSEC-2016-0004](https://rustsec.org/advisories/RUSTSEC-2016-0004.html) |  | libusb is unmaintained; use rusb instead | None |
| 3 | [RUSTSEC-2016-0003](https://rustsec.org/advisories/RUSTSEC-2016-0003.html) | [CVE-2016-10933](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10933)  | HTTP download and execution allows MitM RCE | None |
| 2 | [RUSTSEC-2016-0002](https://rustsec.org/advisories/RUSTSEC-2016-0002.html) | [CVE-2016-10932](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10932)  | HTTPS MitM vulnerability due to lack of hostname verification | None |
| 1 | [RUSTSEC-2016-0001](https://rustsec.org/advisories/RUSTSEC-2016-0001.html) | [CVE-2016-10931](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-10931)  | SSL/TLS MitM vulnerability due to insecure defaults | None |
| 0 | | [CVE-2015-20001](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-20001)  | Panic safety violation in BinaryHeap | None |



## Fuzz

- [rust-fuzz db](https://github.com/rust-fuzz/trophy-case)
- [rustsec advisories](https://rustsec.org/advisories/)
- [rust-fuzz book](https://rust-fuzz.github.io/book/)

### Fuzzer

- [cargo fuzz](https://github.com/rust-fuzz/cargo-fuzz)
- [libfuzzer](https://github.com/rust-fuzz/libfuzzer)
- [afl](https://github.com/rust-fuzz/afl.rs)
- [honggfuzz](https://github.com/rust-fuzz/honggfuzz-rs)

#### Reference

- [Smoke-testing Rust HTTP clients](https://medium.com/@shnatsel/smoke-testing-rust-http-clients-b8f2ee5db4e6)
- [How I’ve found vulnerability in a popular Rust crate ](https://medium.com/@shnatsel/how-ive-found-vulnerability-in-a-popular-rust-crate-and-you-can-too-3db081a67fb)
- [Auditing popular Rust crates: how a one-line unsafe has nearly ruined everything](https://medium.com/@shnatsel/auditing-popular-rust-crates-how-a-one-line-unsafe-has-nearly-ruined-everything-fab2d837ebb1)

