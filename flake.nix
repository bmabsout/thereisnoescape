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

        # Extract package executables
        curl = "${pkgs.curl}/bin/curl";
        jq = "${pkgs.jq}/bin/jq";
        ip = "${pkgs.iproute2}/bin/ip";
        iptables = "${pkgs.iptables}/bin/iptables";
        wgQuick = "${pkgs.wireguard-tools}/bin/wg-quick";
        openvpn = "${pkgs.openvpn}/bin/openvpn";
        bash = "${pkgs.bashInteractive}/bin/bash";
        ping = "${pkgs.iputils}/bin/ping";
        nslookup = "${pkgs.dnsutils}/bin/nslookup";

        runUnderVPN = pkgs.writeShellScriptBin "run-under-vpn" ''
          set -euo pipefail

          CONFIG_FILE=""
          MAIN_IF=""
          VPN_TYPE=""
          VERBOSE=false

          log() { if $VERBOSE; then echo "$@"; fi; }

          check_location() {
            ${curl} -s ipinfo.io | ${jq} -r '"\(.ip) - \(.city), \(.region), \(.country)"' || echo "Location check failed"
          }

          kill_lingering_processes() {
            log "Checking for lingering processes..."
            sudo pkill -f "wg-quick" 2>/dev/null || true
            sudo pkill -f "openvpn" 2>/dev/null || true
          }

          cleanup() {
            log "Cleaning up..."
            kill_lingering_processes
            sudo ${ip} netns del vpn 2>/dev/null || true
            sudo ${ip} link del veth0 2>/dev/null || true
            [ -n "$MAIN_IF" ] && sudo ${iptables} -t nat -D POSTROUTING -s 172.31.255.0/24 -o "$MAIN_IF" -j MASQUERADE 2>/dev/null || true
            sudo rm -rf /etc/netns/vpn 2>/dev/null || true
            cleanup_vpn
          }

          usage() {
            echo "Usage: $0 [-v] -c <config_file> [-- command [args...]]"
            echo "  -v               Verbose mode"
            echo "  -c <config_file> VPN configuration file (.ovpn for OpenVPN, .conf for WireGuard)"
            echo "  -- command [args...] Optional command to run in the VPN namespace"
            exit 1
          }

          setup_wireguard() {
            log "Setting up WireGuard connection..."
            sudo ${ip} netns exec vpn ${wgQuick} up "$CONFIG_FILE"
          }

          setup_openvpn() {
            log "Setting up OpenVPN connection..."
            sudo ${ip} netns exec vpn ${openvpn} --config "$CONFIG_FILE" --daemon --log /tmp/openvpn.log
            for i in {1..30}; do
              if sudo ${ip} netns exec vpn ${ip} addr show | grep -q "tun0"; then
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
            sudo ${ip} netns exec vpn ${wgQuick} down "$CONFIG_FILE" 2>/dev/null || true
            sudo rm -rf /etc/netns/vpn/wireguard /etc/netns/vpn/etc/wireguard 2>/dev/null || true
          }

          cleanup_openvpn() {
            log "Cleaning up OpenVPN connection..."
            sudo pkill -f "openvpn --config $CONFIG_FILE" 2>/dev/null || true
          }

          setup_vpn() {
            if [[ "$VPN_TYPE" == "wireguard" ]]; then
              setup_wireguard
            elif [[ "$VPN_TYPE" == "openvpn" ]]; then
              setup_openvpn
            else
              echo "Error: Unsupported VPN type: $VPN_TYPE"
              exit 1
            fi
          }

          cleanup_vpn() {
            if [[ "$VPN_TYPE" == "wireguard" ]]; then
              cleanup_wireguard
            elif [[ "$VPN_TYPE" == "openvpn" ]]; then
              cleanup_openvpn
            fi
          }

          setup_network() {
            log "Setting up network..."
            sudo ${ip} netns add vpn
            sudo ${ip} -n vpn link set lo up
            MAIN_IF=$(${ip} route | grep default | awk '{print $5}')
            sudo ${ip} link add veth0 type veth peer name veth1
            sudo ${ip} link set veth1 netns vpn
            sudo ${ip} addr add 172.31.255.1/24 dev veth0
            sudo ${ip} link set veth0 up
            sudo ${ip} -n vpn addr add 172.31.255.2/24 dev veth1
            sudo ${ip} -n vpn link set veth1 up
            sudo ${ip} -n vpn route add default via 172.31.255.1
            sudo ${iptables} -t nat -A POSTROUTING -s 172.31.255.0/24 -o "$MAIN_IF" -j MASQUERADE
            echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null
            sudo mkdir -p /etc/netns/vpn
            echo "nameserver 1.1.1.1" | sudo tee /etc/netns/vpn/resolv.conf > /dev/null
            echo "nameserver 1.0.0.1" | sudo tee -a /etc/netns/vpn/resolv.conf > /dev/null
            setup_vpn
          }

          run_in_namespace() {
            if [ $# -eq 0 ]; then
              log "Starting shell in VPN namespace..."
              sudo ${ip} netns exec vpn sudo -u "$USER" ${bash}
            else
              log "Running command in VPN namespace: $*"
              sudo ${ip} netns exec vpn sudo -u "$USER" "$@"
            fi
          }

          main() {
            # Perform initial cleanup
            cleanup

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
            AFTER_LOCATION=$(sudo ${ip} netns exec vpn ${curl} -s ipinfo.io)
            log "$AFTER_LOCATION"

            BEFORE_IP=$(echo "$BEFORE_LOCATION" | awk '{print $1}')
            AFTER_IP=$(echo "$AFTER_LOCATION" | ${jq} -r '.ip' 2>/dev/null || echo "$AFTER_LOCATION" | awk '{print $1}')
            [ "$BEFORE_IP" = "$AFTER_IP" ] && echo "Warning: IP address did not change." || log "IP address changed successfully."

            if $VERBOSE; then
              log "Network namespace information:"
              sudo ${ip} netns exec vpn ${ip} addr show
              sudo ${ip} netns exec vpn ${ip} route show
              log "Running network tests:"
              sudo ${ip} netns exec vpn ${ping} -c 2 1.1.1.1
              sudo ${ip} netns exec vpn ${nslookup} google.com
              sudo ${ip} netns exec vpn ${curl} -I https://www.google.com
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
