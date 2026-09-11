# Known Limitations

- Clean installation only; no in-place upgrade, same-version reinstall, dependency maintenance, updater, or rollback engine.
- No supported product backup/restore, restore cutover, or cross-host migration. A manual host copy or VM snapshot is not automatically a supported recoverable backup.
- No generic Repair, fix-host, orphan adoption, or normalization action.
- No EdgeOne integration in Preview.
- No connector disconnect, logout, reset, rejoin, or rebind automation. Connector mismatches must be resolved outside LanPanel.
- Preview has no live-qualified or hardened-GA OS/package profile claim.
- Tailnet HTTP/WebSocket is reported as not live tested when no independent peer authority is supplied.
- Unpublish, device expiry, and pre-auth key revocation do not guarantee termination of existing flows.
- Key revoke does not expire a registered device.
- Temporary public HTTP is plaintext and does not expire automatically.
- Fail-closed Nginx stop can interrupt Headscale control ingress.
