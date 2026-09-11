# Documentation

LanPanel Preview is managed through its loopback Management UI.

## Public Preview installation

The only public installation path is the official extracted release artifact:

```text
sudo ./lanpanel install
```

The binary discovers its own artifact directory and verifies the canonical `release.json`, detached Ed25519 signature, complete `SHA256SUMS`, fixed Lego/Tailscale/Headscale assets, exact signed `OfficialDistro` package authority, and host profile before mutation. Do not pass bundle paths, release digests, package Plans, dependency paths, Headscale source fields, or ACME contact. The published bootstrap command is version/digest pinned, verifies in a protected temporary directory, and invokes this same command without pipe-to-shell or online fallback.

`sudo lanpanel uninstall` is the only lifecycle removal path. It requires an interactive exact `UNINSTALL LANPANEL` confirmation and removes only committed LanPanel-owned inventory; it does not remove APT/dpkg packages or external application files.

Preview provides basic installation integrity, signed APT, exact package versions, and transaction cleanup. It does not claim hardened GA, complete audit, live qualification, or complete reproducible-release guarantees. Local verification must not require remote installation, DNS/ACME operations, BPF attach, reboot, or publication operations.
