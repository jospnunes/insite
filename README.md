# insite

Full X-ray of a website from the terminal: network, TLS, DNS, stack, security,
SEO and weight, in about a second, from a single binary.

> **Status: early development (v0.1 in progress).** Today insite measures the
> network side: redirect chain, DNS, TCP, TLS and time to first byte per phase,
> HTTP version, IPv6 and whether HTTPS is enforced. TLS, DNS, stack detection
> and the security grade come next. See [docs/arquitetura.md](docs/arquitetura.md)
> (Portuguese) for the full design.

```
$ insite example.com
example.com → https://example.com/  200  HTTP/2  66 ms
  dns 2.4 · tcp 0.5 · tls 2.9 · ttfb 59 · download 0.1
  172.66.147.243 · IPv6 no · HTTP not redirected
```

## Principles

- **Fast enough to be a selling point**, measured and published.
- **Correct before fast.** No finding without evidence; what could not be
  measured is shown as not measured, never as absent.
- **Passive.** It reads what any visitor would see. No port scans, no path
  fuzzing, no vulnerability tests.

## Build

```bash
cargo build --release
./target/release/insite example.com
```

Options so far: `--json`, `--timeout <seconds>`, `--ua hybrid|chrome|honest|<text>`,
`--lang <tag>`. Exit codes: 0 complete, 1 unreachable, 2 usage error, 3 partial.

## License

GPL-3.0-or-later. The stack detection will embed the
[webappanalyzer](https://github.com/enthec/webappanalyzer) signatures, which are
GPL-3.0.

---

## Em português

Raio-x completo de um site pelo terminal: rede, TLS, DNS, stack, segurança, SEO
e peso, em cerca de um segundo, num binário único.

**Estado: em desenvolvimento (v0.1).** Hoje o insite mede a parte de rede:
cadeia de redirects, tempo de DNS, TCP, TLS e primeiro byte por fase, versão do
HTTP, IPv6 e se o HTTPS é forçado. TLS, DNS, detecção de stack e nota de
segurança vêm em seguida. O desenho completo está em
[docs/arquitetura.md](docs/arquitetura.md).

Compilar: `cargo build --release`. Licença GPL-3.0-or-later.
