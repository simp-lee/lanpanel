# Known Limitations

- Clean installation only; no in-place upgrade, same-version reinstall, dependency maintenance, updater, or rollback engine.
- No supported product backup/restore, restore cutover, or cross-host migration.
- No generic Repair, fix-host, orphan adoption, or normalization action.
- No EdgeOne integration in the first Community GA.
- No connector disconnect, logout, reset, rejoin, or rebind automation. Connector mismatches must be resolved outside LanPanel.
- One Linux amd64 OS/package profile is supported only after this exact binary completes live qualification.
- Tailnet HTTP/WebSocket is reported as not live tested when no independent peer authority is supplied.
- Unpublish, device expiry, and pre-auth key revocation do not guarantee termination of existing flows.
- Temporary public HTTP is plaintext and does not expire automatically.
- Fail-closed Nginx stop can interrupt Headscale control ingress.
