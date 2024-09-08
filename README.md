# WireGuard VPN Network Namespace Runner

This project provides a Nix flake that creates an isolated network namespace with a WireGuard VPN connection. It allows you to run commands or start an interactive shell within this isolated environment, ensuring that all network traffic from the specified processes goes through the VPN.

## Features

- Creates an isolated network namespace for VPN traffic
- Sets up a WireGuard VPN connection within the namespace
- Allows running specific commands or an interactive shell in the VPN environment
- Cleans up the namespace and VPN connection automatically on exit
- Provides location checks before and after VPN connection

## Requirements

- Nix package manager with flakes enabled
- WireGuard tools
- Root privileges (sudo access)

## Usage

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/wireguard-vpn-namespace.git
   cd wireguard-vpn-namespace
   ```

2. Prepare your WireGuard configuration file (e.g., `wg0.conf`).

3. Run a command in the VPN namespace:
   ```
   nix run . -- -c /path/to/your/wg0.conf curl ipinfo.io
   ```

4. Or start an interactive shell in the VPN namespace:
   ```
   nix run . -- -c /path/to/your/wg0.conf
   ```

## How it Works

1. The script creates a new network namespace.
2. It sets up a WireGuard interface within this namespace using the provided configuration.
3. All DNS queries within the namespace are directed to 1.1.1.1.
4. The script then either runs the specified command or starts an interactive shell within this namespace.
5. Upon exit, the namespace and VPN connection are cleaned up automatically.

## Security Considerations

- The WireGuard configuration file contains sensitive information. Ensure it has appropriate permissions (600) and is stored securely.
- This script requires root privileges to set up the network namespace and WireGuard interface. Use with caution and only with trusted WireGuard configurations.

## Limitations

- The current implementation does not support IPv6. Only IPv4 traffic is routed through the VPN.
- Some applications may not work correctly in the isolated namespace if they require specific network configurations.

## Contributing

Contributions to improve the script or add features are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.