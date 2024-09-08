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
          VPN_TYPE=""
          VERBOSE=false

          log() { if $VERBOSE; then echo "$@"; fi; }

          check_location() {
            ${pkgs.curl}/bin/curl -s ipinfo.io | ${pkgs.jq}/bin/jq -r '"\(.ip) - \(.city), \(.region), \(.country)"' || echo "Location check failed"
          }

          cleanup() {
            log "Cleaning up..."
            sudo ${pkgs.iproute2}/bin/ip netns del vpn 2>/dev/null || true
            sudo ${pkgs.iproute2}/bin/ip link del veth0 2>/dev/null || true
            [ -n "$MAIN_IF" ] && sudo ${pkgs.iptables}/bin/iptables -t nat -D POSTROUTING -s 10.0.0.0/24 -o "$MAIN_IF" -j MASQUERADE 2>/dev/null || true
            cleanup_vpn
          }

          usage() {
            echo "Usage: $0 [-v] -c <config_file> [-- command [args...]]"
            echo "  -v               Verbose mode"
            echo "  -c <config_file> VPN configuration file (.ovpn for OpenVPN, .conf for WireGuard)"
            echo "  -- command [args...] Optional command to run in the VPN namespace"
            exit 1
          }

          declare -A vpn_setup_functions
          declare -A vpn_cleanup_functions

          vpn_setup_functions["wireguard"]="setup_wireguard"
          vpn_setup_functions["openvpn"]="setup_openvpn"

          vpn_cleanup_functions["wireguard"]="cleanup_wireguard"
          vpn_cleanup_functions["openvpn"]="cleanup_openvpn"

          setup_wireguard() {
            log "Setting up WireGuard connection..."
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.wireguard-tools}/bin/wg-quick up "$CONFIG_FILE"
          }

          setup_openvpn() {
            log "Setting up OpenVPN connection..."
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.openvpn}/bin/openvpn --config "$CONFIG_FILE" --daemon --log /tmp/openvpn.log
            for i in {1..30}; do
              if sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip addr show | grep -q "tun0"; then
                log "OpenVPN connection established."
                return 0
              fi
              sleep 1
            done
            echo "Error: OpenVPN connection failed to establish within 30 seconds."
            return 1
          }

          cleanup_wireguard() {
            log "Cleaning up WireGuard connection..."
            sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.wireguard-tools}/bin/wg-quick down "$CONFIG_FILE" 2>/dev/null || true
          }

          cleanup_openvpn() {
            log "Cleaning up OpenVPN connection..."
            sudo pkill -f "openvpn --config $CONFIG_FILE" 2>/dev/null || true
          }

          setup_vpn() {
            if [[ -n "''${vpn_setup_functions[$VPN_TYPE]}" ]]; then
              "''${vpn_setup_functions[$VPN_TYPE]}"
            else
              echo "Error: Unsupported VPN type: $VPN_TYPE"
              exit 1
            fi
          }

          cleanup_vpn() {
            if [[ -n "''${vpn_cleanup_functions[$VPN_TYPE]}" ]]; then
              "''${vpn_cleanup_functions[$VPN_TYPE]}"
            fi
          }

          setup_network() {
            log "Setting up network..."
            sudo ${pkgs.iproute2}/bin/ip netns add vpn
            sudo ${pkgs.iproute2}/bin/ip -n vpn link set lo up
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
            echo "nameserver 1.1.1.1" | sudo tee /etc/netns/vpn/resolv.conf > /dev/null
            echo "nameserver 1.0.0.1" | sudo tee -a /etc/netns/vpn/resolv.conf > /dev/null
            setup_vpn
          }

          run_in_namespace() {
            if [ $# -eq 0 ]; then
              log "Starting shell in VPN namespace..."
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn sudo -u "$USER" ${pkgs.bashInteractive}/bin/bash
            else
              log "Running command in VPN namespace: $*"
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn sudo -u "$USER" "$@"
            fi
          }

          main() {
            local COMMAND=()

            while [[ $# -gt 0 ]]; do
              case $1 in
                -v) VERBOSE=true; shift ;;
                -c) CONFIG_FILE="$2"; shift 2 ;;
                --) shift; COMMAND=("$@"); break ;;
                *) COMMAND+=("$1"); shift ;;
              esac
            done

            [ -z "$CONFIG_FILE" ] && usage
            CONFIG_FILE=$(realpath "$CONFIG_FILE")
            [ ! -f "$CONFIG_FILE" ] && echo "Error: Configuration file '$CONFIG_FILE' not found." && exit 1

            case ''${CONFIG_FILE##*.} in
              conf) VPN_TYPE="wireguard" ;;
              ovpn) VPN_TYPE="openvpn" ;;
              *) echo "Error: Unsupported configuration file format." && exit 1 ;;
            esac

            trap cleanup EXIT INT TERM

            log "Checking location before VPN connection:"
            BEFORE_LOCATION=$(check_location)
            log "$BEFORE_LOCATION"

            sudo -v
            setup_network

            log "Checking location after VPN connection:"
            AFTER_LOCATION=$(sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.curl}/bin/curl -s ipinfo.io)
            log "$AFTER_LOCATION"

            BEFORE_IP=$(echo "$BEFORE_LOCATION" | awk '{print $1}')
            AFTER_IP=$(echo "$AFTER_LOCATION" | ${pkgs.jq}/bin/jq -r '.ip' 2>/dev/null || echo "$AFTER_LOCATION" | awk '{print $1}')
            [ "$BEFORE_IP" = "$AFTER_IP" ] && echo "Warning: IP address did not change." || log "IP address changed successfully."

            if $VERBOSE; then
              log "Network namespace information:"
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip addr show
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iproute2}/bin/ip route show
              log "Running network tests:"
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.iputils}/bin/ping -c 2 1.1.1.1
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.dnsutils}/bin/nslookup google.com
              sudo ${pkgs.iproute2}/bin/ip netns exec vpn ${pkgs.curl}/bin/curl -I https://www.google.com
            fi

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
        apps.default = flake-utils.lib.mkApp { drv = runUnderVPN; };
      }
    );
}
