This directory stores PCAP fixtures used by inspector integration tests.

Current fixtures:
- bittorrent.pcap: packet with BitTorrent handshake signature (expected inspector verdict: drop, reason=bittorrent_signature)
- tls_blocked.pcap: TLS ClientHello with blocked SNI (expected verdict: drop, reason=tls_sni_blocked)
- http_blocked.pcap: HTTP request with blocked Host header (expected verdict: drop, reason=http_host_blocked)
- openvpn.pcap: OpenVPN traffic from /docker/pcap/openvpn (expected verdict: drop, reason=openvpn_signature)

These fixtures are consumed by:
- tests/integration/inspector_pcap_integration_test.go
