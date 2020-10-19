## Rust-Security

Rust Language Security

  
execrices: [rust-ctf](https://github.com/xxg1413/rust-ctf)

## CVE

## Rust-lang

| ID | CVE-ID  |    Description    |  Analysis      |
|----|---------|    -------------  |  ------------  |
| 6 | [CVE-2019-1010299](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-CVE-2019-1010299) | Obtain Information | None |
| 5 | [CVE-2019-16760](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16760) | Cargo download the wrong dependency | None |
| 4 | [CVE-2019-12083](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-12083) | IOverflow  | None |
| 3 | [CVE-2018-1000810](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000810) | Integer Overflow to Buffer Overflow  | None |
| 2 | [CVE-2018-1000657](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000657) | Buffer Overflow | None |
| 1 | [CVE-2018-1000622](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-1000622) | Uncontrolled Search Path Element | None |


## Rust Crates

- [rust-base64: CVE-2017-1000430](#rust-base64)

### rust-base64

- [CVE-2017-1000430](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-1000430): Integer overflow leads to heap-based buffer overflow in encode_config_buf



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

