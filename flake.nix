{
  description = "Run a command or shell under WireGuard or OpenVPN in a network namespace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        runUnderVPN = pkgs.writeShellScriptBin "run-under-vpn" ''
          set -euo pipefail

          check_location() {
            echo "Checking location..."
            timeout 10 ${pkgs.curl}/bin/curl -s ipinfo.io | ${pkgs.jq}/bin/jq -r '"\(.ip) - \(.city), \(.region), \(.country)"' || echo "Location check failed"
          }

          cleanup() {
            echo "Cleaning up..."
            sudo ${pkgs.iproute2}/bin/ip netns del vpn 2>/dev/null || true
            sudo ${pkgs.iproute2}/bin/ip link del veth0 2>/dev/null || true
            sudo ${pkgs.iptables}/bin/iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o "$MAIN_IF" -j MASQUERADE 2>/dev/null || true
          }

          usage() {
            echo "Usage: $0 -c <config_file> [command]"
            echo "  -c <config_file>  Specify the WireGuard configuration file (full path)"
            echo "  [command]         Optional command to run in the VPN namespace"
            exit 1
          }

          setup_network() {
            echo "Creating network namespace..."
            sudo ${pkgs.iproute2}/bin/ip netns add vpn
            sudo ${pkgs.iproute2}/bin/ip -n vpn link set lo up

            echo "Setting up VPN connection..."
            if [[ "$CONFIG_FILE" == *.conf ]]; then
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.openvpn}/bin/openvpn --config "$CONFIG_FILE" --daemon
            elif [[ "$CONFIG_FILE" == *.wg ]]; then
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.wireguard-tools}/bin/wg-quick up "$CONFIG_FILE"
            else
              echo "Error: Unsupported configuration file format. Use .conf for OpenVPN or .wg for WireGuard."
              exit 1
            fi

            echo "Configuring network..."
            MAIN_IF=$(ip route | grep default | awk '{print $5}')
            sudo ${pkgs.iproute2}/bin/ip link add veth0 type veth peer name veth1
            sudo ${pkgs.iproute2}/bin/ip link set veth1 netns vpn
            sudo ${pkgs.iproute2}/bin/ip addr add 10.0.0.1/24 dev veth0
            sudo ${pkgs.iproute2}/bin/ip link set veth0 up
            sudo ${pkgs.iproute2}/bin/ip -n vpn addr add 10.0.0.2/24 dev veth1
            sudo ${pkgs.iproute2}/bin/ip -n vpn link set veth1 up
            sudo ${pkgs.iproute2}/bin/ip -n vpn route add default via 10.0.0.1
            sudo ${pkgs.iptables}/bin/iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$MAIN_IF" -j MASQUERADE
            echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
          }

          run_in_namespace() {
            if [ $# -eq 0 ]; then
              echo "Starting shell in VPN namespace. Type 'exit' to leave and clean up."
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn sudo -u "$USER" ${pkgs.bashInteractive}/bin/bash
            else
              echo "Running command in VPN namespace: $*"
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn sudo -u "$USER" "$@"
            fi
          }

          main() {
            # Parse command line arguments
            while getopts "c:" opt; do
              case $opt in
                c) CONFIG_FILE="$OPTARG" ;;
                *) usage ;;
              esac
            done
            shift $((OPTIND - 1))

            if [ -z "''${CONFIG_FILE:-}" ]; then
              usage
            fi

            # Ensure CONFIG_FILE is an absolute path
            CONFIG_FILE=$(realpath "$CONFIG_FILE")

            if [ ! -f "$CONFIG_FILE" ]; then
              echo "Error: Configuration file '$CONFIG_FILE' not found."
              exit 1
            fi

            if [[ "$CONFIG_FILE" != *.conf && "$CONFIG_FILE" != *.wg ]]; then
              echo "Error: Unsupported configuration file format. Use .conf for OpenVPN or .wg for WireGuard."
              exit 1
            }

            trap cleanup EXIT INT TERM

            echo "Attempting to check location before VPN connection:"
            check_location

            # Ask for sudo password upfront
            sudo -v

            setup_network

            echo "Attempting to check location after VPN connection:"
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.curl}/bin/curl -s ipinfo.io | ${pkgs.jq}/bin/jq -r '"\(.ip) - \(.city), \(.region), \(.country)"' || echo "Location check failed"

            run_in_namespace "$@"
          }

          main "$@"
        '';

      in
      {
        packages.default = runUnderVPN;

        apps.default = {
          type = "app";
          program = "${runUnderVPN}/bin/run-under-vpn";
        };
      }
    );
}
