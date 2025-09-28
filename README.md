# Ignite: Authority Chain Management CLI

## Project Overview

Ignite is a robust, security-focused CLI tool designed for managing authority chains within the Padlock ecosystem. As a critical component of the RSB (Reliable Secure Bootstrap) framework, Ignite provides a comprehensive solution for lifecycle management of cryptographic identities and access controls.

### Key Features

- **Authority Chain Management**: Implement and manage hierarchical key lifecycles
- **Secure Key Rotation**: Cryptographically sound key generation and rotation mechanisms
- **CLI-Driven Workflow**: Automation-friendly command-line interfaces
- **Manifest-Based Access Control**: Define and enforce access policies through cryptographic manifests
- **Policy Engine Enforcement**: Apply expiration and passphrase-strength policies at key creation time

### Authority Chain Hierarchy

Ignite implements a structured authority chain with the following levels:
- X (Root/Master Authority)
- M (Management Level)
- R (Rotation Level)
- I (Intermediate Level)
- D (Delegation/End-User Level)

## Installation & Setup

### Requirements

- Rust (2021 edition)
- Cargo package manager
- OpenSSL development libraries

### Build Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/padlokk/ignite.git
   cd ignite
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. Install the CLI:
   ```bash
   cargo install --path .
   ```

### Initial Configuration

After installation, you can start using the CLI immediately:

```bash
ignite status
```

## Usage Guide

### Basic CLI Commands

1. Create a new authority key (policies enforce expiration defaults and passphrase rules):
   ```bash
   ignite create --key-type master --description "Primary authority key"
   ```

2. List existing keys:
   ```bash
   ignite list
   ignite list --key-type master  # Filter by type
   ```

3. Check authority chain status:
   ```bash
   ignite status
   ```

4. Verify a manifest file:
   ```bash
   ignite verify /path/to/manifest.json
   ```

### Available Key Types

- `skull` - Ultimate authority (emergency recovery)
- `master` - Global authority (system administration)
- `repo` - Repository authority (local management)
- `ignition` - Authority bridge (automation access)
- `distro` - Distributed access (third party access)

### Common Workflows

- **Key Management**: Create, list, rotate, and revoke cryptographic keys
- **Authority Chain Configuration**: Define and manage hierarchical access structures
- **Manifest Generation**: Create cryptographically signed access manifests

## Architecture Overview

### Components

- **CLI Module**: Command-line interface and user interactions (RSB bootstrap/options!/dispatch!)
- **Authority Module**: Key lifecycle and chain management (AuthorityChain DAG, proofs, manifests)
- **Security Module**: Modular `PolicyEngine` orchestrating expiration & passphrase policies
- **Storage Adapters**: Flexible key storage (XDG, local filesystem)

### Security Model

- Ed25519 elliptic curve cryptography
- Manifest-based access control
- Cryptographic proof generation and validation

### Storage System

- Encrypted key vault
- Supports multiple storage backends
- Secure key rotation and revocation mechanisms

## Development Information

### Project Structure

- `src/`: Main source code
  - `bin/`: CLI entry points
  - `ignite/`: Core module implementations
- `docs/`: Project documentation
- `tests/`: Unit and integration tests

### Testing

Run the test suite:
```bash
cargo test
```

### Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push and submit a pull request

Please adhere to the project's coding standards and include appropriate tests.

## Licensing

This project is licensed under the AGPL-3.0 License. See the LICENSE file for details.

## Contact & Support

For issues, feature requests, or support, please file an issue on the GitHub repository.

## Acknowledgments

Part of the Padlock security ecosystem, built with support from the RSB framework.
