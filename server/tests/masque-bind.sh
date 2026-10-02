#!/bin/sh
set -eu

. "$(dirname "$0")/../masque-bind.sh"

test_legacy_masque_port_moves_away_from_proxy_udp() {
    result="$(resolve_masque_bind 0.0.0.0:443 443 8443)"
    [ "$result" = "0.0.0.0:8444" ]
}

test_masque_port_moves_away_from_mesh_quic() {
    result="$(resolve_masque_bind 0.0.0.0:8443 443 8443)"
    [ "$result" = "0.0.0.0:8444" ]
}

test_custom_non_conflicting_bind_is_preserved() {
    result="$(resolve_masque_bind 127.0.0.1:9443 443 8443)"
    [ "$result" = "127.0.0.1:9443" ]
}

test_masque_port_skips_both_conflicting_ports() {
    result="$(resolve_masque_bind 0.0.0.0:8444 8444 8443)"
    [ "$result" = "0.0.0.0:8445" ]
}

test_legacy_masque_port_moves_away_from_proxy_udp
test_masque_port_moves_away_from_mesh_quic
test_custom_non_conflicting_bind_is_preserved
test_masque_port_skips_both_conflicting_ports
