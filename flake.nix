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

          CONFIG_FILE=""
          MAIN_IF=""

          check_location() {
            echo "Checking location..."
            timeout 10 ${pkgs.curl}/bin/curl -s ipinfo.io | ${pkgs.jq}/bin/jq -r '"\(.ip) - \(.city), \(.region), \(.country)"' || echo "Location check failed"
          }

          cleanup() {
            echo "Cleaning up..."
            sudo ${pkgs.iproute2}/bin/ip netns del vpn 2>/dev/null || true
            sudo ${pkgs.iproute2}/bin/ip link del veth0 2>/dev/null || true
            if [ -n "$MAIN_IF" ]; then
              sudo ${pkgs.iptables}/bin/iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o "$MAIN_IF" -j MASQUERADE 2>/dev/null || true
            fi
            if [ -n "$CONFIG_FILE" ] && [[ "$CONFIG_FILE" == *.ovpn ]]; then
              sudo pkill -f "openvpn --config $CONFIG_FILE" 2>/dev/null || true
            fi
          }

          usage() {
            echo "Usage: $0 -c <config_file> [command [args...]]"
            echo "  -c <config_file>  Specify the VPN configuration file (full path, .ovpn for OpenVPN or .conf for WireGuard)"
            echo "  [command [args...]]  Optional command with arguments to run in the VPN namespace"
            exit 1
          }

          setup_network() {
            echo "Creating network namespace..."
            sudo ${pkgs.iproute2}/bin/ip netns add vpn
            sudo ${pkgs.iproute2}/bin/ip -n vpn link set lo up

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

            # Copy resolv.conf to the namespace to ensure DNS resolution works
            sudo mkdir -p /etc/netns/vpn
            sudo cp /etc/resolv.conf /etc/netns/vpn/resolv.conf

            # Ensure DNS is properly configured
            echo "Configuring DNS..."
            sudo mkdir -p /etc/netns/vpn
            echo "nameserver 1.1.1.1" | sudo tee /etc/netns/vpn/resolv.conf > /dev/null
            echo "nameserver 1.0.0.1" | sudo tee -a /etc/netns/vpn/resolv.conf > /dev/null

            echo "Setting up VPN connection..."
            if [[ "$CONFIG_FILE" == *.ovpn ]]; then
              # Run OpenVPN in the background
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.openvpn}/bin/openvpn --config "$CONFIG_FILE" --daemon --log /tmp/openvpn.log
              
              # Wait for the connection to establish
              echo "Waiting for OpenVPN to establish connection..."
              for i in {1..30}; do
                if sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip addr show | grep -q "tun0"; then
                  echo "OpenVPN connection established."
                  break
                fi
                if ! pgrep -f "openvpn --config $CONFIG_FILE" > /dev/null; then
                  echo "Error: OpenVPN process terminated unexpectedly. Check /tmp/openvpn.log for details."
                  exit 1
                fi
                sleep 1
              done

              if ! sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip addr show | grep -q "tun0"; then
                echo "Error: OpenVPN connection failed to establish within 30 seconds."
                exit 1
              fi
            elif [[ "$CONFIG_FILE" == *.conf ]]; then
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.wireguard-tools}/bin/wg-quick up "$CONFIG_FILE"
            else
              echo "Error: Unsupported configuration file format. Use .ovpn for OpenVPN or .conf for WireGuard."
              exit 1
            fi
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

          test_network() {
            echo "Testing network connectivity..."
            echo "Ping test:"
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iputils}/bin/ping -c 4 1.1.1.1
            echo "DNS resolution test:"
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.dnsutils}/bin/nslookup google.com
            echo "HTTP test:"
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.curl}/bin/curl -I https://www.google.com
          }

          main() {
            local COMMAND=()

            # Parse command line arguments
            while [[ $# -gt 0 ]]; do
              case $1 in
                -c)
                  CONFIG_FILE="$2"
                  shift 2
                  ;;
                --)
                  shift
                  COMMAND=("$@")
                  break
                  ;;
                *)
                  COMMAND+=("$1")
                  shift
                  ;;
              esac
            done

            if [ -z "$CONFIG_FILE" ]; then
              usage
            fi

            # Ensure CONFIG_FILE is an absolute path
            CONFIG_FILE=$(realpath "$CONFIG_FILE")

            if [ ! -f "$CONFIG_FILE" ]; then
              echo "Error: Configuration file '$CONFIG_FILE' not found."
              exit 1
            fi

            if [[ "$CONFIG_FILE" != *.ovpn && "$CONFIG_FILE" != *.conf ]]; then
              echo "Error: Unsupported configuration file format. Use .ovpn for OpenVPN or .conf for WireGuard."
              exit 1
            fi

            trap cleanup EXIT INT TERM

            echo "Attempting to check location before VPN connection:"
            BEFORE_LOCATION=$(check_location)

            # Ask for sudo password upfront
            sudo -v

            setup_network

            echo "Attempting to check location after VPN connection:"
            AFTER_LOCATION=$(sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.curl}/bin/curl -s ipinfo.io)
            echo "Raw response from ipinfo.io:"
            echo "$AFTER_LOCATION"
            
            if echo "$AFTER_LOCATION" | ${pkgs.jq}/bin/jq -e . > /dev/null 2>&1; then
              LOCATION_INFO=$(echo "$AFTER_LOCATION" | ${pkgs.jq}/bin/jq -r '"\(.ip) - \(.city), \(.region), \(.country)"')
            else
              LOCATION_INFO=$(echo "$AFTER_LOCATION" | tr -d '\n')
            fi
            echo "Location after VPN: $LOCATION_INFO"
            
            # Verify that the IP has changed
            BEFORE_IP=$(echo "$BEFORE_LOCATION" | ${pkgs.jq}/bin/jq -r '.ip' 2>/dev/null || echo "$BEFORE_LOCATION" | awk '{print $1}')
            AFTER_IP=$(echo "$AFTER_LOCATION" | ${pkgs.jq}/bin/jq -r '.ip' 2>/dev/null || echo "$AFTER_LOCATION" | awk '{print $1}')
            if [ "$BEFORE_IP" = "$AFTER_IP" ]; then
              echo "Warning: VPN connection might have failed. IP address did not change."
            else
              echo "IP address changed successfully."
            fi

            echo "Dumping network namespace information:"
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip addr show
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip route show

            echo "VPN connection established. Running network tests:"
            test_network

            if [ ''${#COMMAND[@]} -eq 0 ]; then
              run_in_namespace
            else
              run_in_namespace "''${COMMAND[@]}"
            fi
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
