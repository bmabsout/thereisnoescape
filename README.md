# VPN Network Namespace Runner

This project provides a Nix flake that creates an isolated network namespace with either a WireGuard or OpenVPN connection. It allows you to run commands or start an interactive shell within this isolated environment, ensuring that all network traffic from the specified processes goes through the VPN.

## Features

- Creates an isolated network namespace for VPN traffic
- Supports both WireGuard and OpenVPN connections
- Sets up the VPN connection within the namespace
- Allows running specific commands or an interactive shell in the VPN environment
- Cleans up the namespace and VPN connection automatically on exit
- Provides location checks before and after VPN connection
- Performs network tests to verify the VPN connection

## Requirements

- Nix package manager with flakes enabled
- WireGuard tools (for WireGuard connections)
- OpenVPN (for OpenVPN connections)
- Root privileges (sudo access)

## Usage

1. Prepare your VPN configuration file:
   - For WireGuard: `your_config.conf`
   - For OpenVPN: `your_config.ovpn`

2. Run a command in the VPN namespace:
   ```
   nix run github:bmabsout/thereisnoescape -- -c /path/to/your/config.conf -- curl ipinfo.io
   ```
   or with verbose output:
   ```
   nix run github:bmabsout/thereisnoescape -- -v -c /path/to/your/config.conf -- curl ipinfo.io
   ```

3. Or start an interactive shell in the VPN namespace:
   ```
   nix run github:bmabsout/thereisnoescape -- -c /path/to/your/config.conf
   ```

Note: Use the `-v` flag for verbose output and additional network tests.

## How it Works

1. The script creates a new network namespace.
2. It sets up either a WireGuard or OpenVPN interface within this namespace using the provided configuration.
3. DNS queries within the namespace are directed to 1.1.1.1 and 1.0.0.1.
4. The script performs network tests to verify the VPN connection.
5. It then either runs the specified command or starts an interactive shell within this namespace.
6. Upon exit, the namespace and VPN connection are cleaned up automatically.

## Security Considerations

- The VPN configuration file contains sensitive information. Ensure it has appropriate permissions (600) and is stored securely.
- This script requires root privileges to set up the network namespace and VPN interface. Use with caution and only with trusted VPN configurations.

## Limitations

- Some applications may not work correctly in the isolated namespace if they require specific network configurations.

## Contributing

Contributions to improve the script or add features are welcome. Please submit a pull request or open an issue to discuss proposed changes.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.