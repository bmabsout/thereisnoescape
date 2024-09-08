{
  description = "Run a command or shell under WireGuard VPN in a network namespace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};

        runUnderVPN = pkgs.writeShellScriptBin "run-under-vpn" ''
          set -e

          check_location() {
            echo "Checking location..."
            timeout 10 ${pkgs.curl}/bin/curl -s ipinfo.io | ${pkgs.jq}/bin/jq -r '"\(.ip) - \(.city), \(.region), \(.country)"' || echo "Location check failed"
          }

          cleanup() {
            echo "Cleaning up..."
            sudo ${pkgs.iproute2}/bin/ip netns del vpn 2>/dev/null || true
            sudo ${pkgs.iproute2}/bin/ip link del veth0 2>/dev/null || true
            sudo ${pkgs.iptables}/bin/iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o "$INTERFACE" -j MASQUERADE 2>/dev/null || true
          }

          create_network_namespace() {
            echo "Creating network namespace..."
            sudo ${pkgs.iproute2}/bin/ip netns add vpn
            sudo ${pkgs.iproute2}/bin/ip link add veth0 type veth peer name veth1
            sudo ${pkgs.iproute2}/bin/ip link set veth1 netns vpn
            sudo ${pkgs.iproute2}/bin/ip addr add 10.0.0.1/24 dev veth0
            sudo ${pkgs.iproute2}/bin/ip link set veth0 up
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip addr add 10.0.0.2/24 dev veth1
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip link set veth1 up
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip route add default via 10.0.0.1

            # Enable IP forwarding
            echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

            # Set up NAT
            sudo ${pkgs.iptables}/bin/iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o "$INTERFACE" -j MASQUERADE
          }

          usage() {
            echo "Usage: $0 -c <config_file> [command]"
            echo "  -c <config_file>  Specify the WireGuard configuration file (full path)"
            echo "  [command]         Optional command to run in the VPN namespace"
            exit 1
          }

          # Parse command line arguments
          while getopts "c:" opt; do
            case $opt in
              c) CONFIG_FILE="$OPTARG" ;;
              *) usage ;;
            esac
          done
          shift $((OPTIND - 1))

          if [ -z "$CONFIG_FILE" ]; then
            usage
          fi

          # Ensure CONFIG_FILE is an absolute path
          CONFIG_FILE=$(realpath "$CONFIG_FILE")

          if [ ! -f "$CONFIG_FILE" ]; then
            echo "Error: Configuration file '$CONFIG_FILE' not found."
            exit 1
          fi

          # Debug output
          echo "Debug: CONFIG_FILE = $CONFIG_FILE"
          echo "Debug: File contents:"
          cat "$CONFIG_FILE"

          trap cleanup EXIT INT TERM

          # Ask for sudo password upfront
          sudo -v

          echo "Attempting to check location before VPN connection:"
          check_location || echo "Skipping initial location check"

          INTERFACE=$(ip route get 1.1.1.1 | awk '{print $5; exit}')

          create_network_namespace

          echo "Setting up WireGuard connection..."
          echo "Debug: Running command: sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.wireguard-tools}/bin/wg-quick up \"$CONFIG_FILE\""
          sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.wireguard-tools}/bin/wg-quick up "$CONFIG_FILE"

          echo "Attempting to check location after VPN connection:"
          sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.curl}/bin/curl -s ipinfo.io | ${pkgs.jq}/bin/jq -r '"\(.ip) - \(.city), \(.region), \(.country)"' || echo "Location check failed"

          if [ $# -eq 0 ]; then
            echo "Starting shell in VPN namespace. Type 'exit' to leave and clean up."
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn sudo -u $USER ${pkgs.bashInteractive}/bin/bash
          else
            echo "Running command in VPN namespace: $@"
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn sudo -u $USER "$@"
          fi
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
