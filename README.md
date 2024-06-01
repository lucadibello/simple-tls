# simple-tls

## Overview

simple-tls is a lightweight and straightforward implementation of the TLS (Transport Layer Security) protocol. This project aims to provide a minimalistic yet functional example of TLS communication, demonstrating key aspects such as encryption, decryption, and certificate handling.

## Features

- Basic TLS client and server implementation
- Support for AES encryption
- Certificate handling using OpenSSL
- Simple handshake mechanism

## Requirements

- gcc (GNU Compiler Collection)
- OpenSSL library
- make (build automation tool)
- Homebrew (for macOS)

## Installation

### macOS

1. Install Homebrew if you haven't already:

```sh
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

2. Install OpenSSL using Homebrew:

```sh
brew install openssl
```

3. Clone the repository:

```sh
git clone https://github.com/yourusername/simple-tls.git
cd simple-tls
```

4. Build the project:

```sh
make
```

### Linux

1. Install OpenSSL and gcc if you haven't already:

```sh
sudo apt-get update
sudo apt-get install -y openssl libssl-dev gcc make
```

2. Clone the repository:

```sh
git clone https://github.com/yourusername/simple-tls.git
cd simple-tls
```

3. Build the project:

```sh
make
```

## Usage

### Running the Client

```sh
./build/simple_tls
```

### Running the Server

```sh
./build/tls_server
```

## Testing

The project includes unit tests to ensure the correct functionality of various components. To run the tests, use the following commands:

```sh
make check
```

To run tests with Valgrind for memory leak detection:

```sh
make check-valgrind
```

## Project Structure

- `src/`: Contains the source code for the TLS implementation.
- `test/`: Contains unit tests for the project.
- `build/`: Directory where the compiled binaries and object files are placed.
- `unity/`: Directory containing the Unity testing framework.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Acknowledgements

This project uses the OpenSSL library for cryptographic operations and the Unity framework for unit testing.
