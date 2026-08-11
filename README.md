# LanPanel

LanPanel is a community, MIT-licensed management application for a local Headscale installation and published applications.

The release architecture uses one binary with a closed set of separately supervised process roles. The Management UI is the only supported management interface. Data-plane services and timer roles are supervised independently, so stopping or restarting the UI does not stop existing ingress, Headscale, connectors, managed processes, analytics, or certificate renewal.

The product is being rebuilt against the GA safety and qualification contract. Operational roles remain unavailable until their complete typed handlers and release qualification are present. There is no supported command-line, JSON, or YAML management interface.

See [LICENSE](LICENSE).
