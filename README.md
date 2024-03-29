[![Go Report Card](https://goreportcard.com/badge/github.com/ThalesGroup/ciphertrust-kms-spire-plugin)](https://goreportcard.com/report/github.com/ThalesGroup/ciphertrust-kms-spire-plugin)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/ThalesGroup/ciphertrust-kms-spire-plugin/blob/main/LICENSE)
# SPIRE Ciphertrust KMS Plugin

This repository contains an external Key Manager plugin using Thales CipherTrust KMS for [SPIRE](https://github.com/spiffe/spire). 

* Thales CipherTrust Manager is an independent 3rd party tool dedicated to efficiently managing keys on behalf of SPIRE.
* It enables the initial enrollment of the SPIRE server architecture.
* CipherTrust KMS provides the Root Key and the keys identifiers.

## Menu

- [Prerequisite](#prerequisite)
- [Quick start](#quick-start)
- [How it Works](#how-it-works)
- [Building](#building)
- [Testing](#testing)
- [License](#license)
- [Contributing](#contributing)
- [Security Vulnerability Reporting](#security-vulnerability-reporting)

## Demo

Here's a quick demo that shows how this plugin looks when run:
![Plugin in action](assets/ciphertrust-plugin.gif)

The demo commands can be found on the [SPIRE getting started](https://spiffe.io/docs/latest/try/getting-started-linux-macos-x/)

## Get started

### Prerequisite

#### CipherTrust Manager Setup

There are 3 options to setup a CipherTrust Manager instance.

1. [Locally using Virtual Box](https://www.youtube.com/watch?v=MNFgVhgMLB4&list=PLw3mEF7reqIN7TKqwUoCTM9dkFA9xer_0&index=8)

2. [Host on Azure](https://www.youtube.com/watch?v=2TcaAjfqaEE&list=PLw3mEF7reqIM6TdatdDSd5G_tvsNVqNhx)

3. [As a service](https://cpl.thalesgroup.com/encryption/data-security-platform/ciphertrust-encryption-key-management-service#start)

### Quick Start

Before starting, create a running SPIRE deployment and add the following configuration to the agent and server:

### Server Configuration

```hcl
 KeyManager "ciphertrust_kms" {
	plugin_cmd = "/path/to/plugin_cmd"              <- a binary is provided in the bin folder
	plugin_checksum = "sha256 of the plugin binary" <- the hash is provided in the bin folder
	plugin_data = {
         key_metadata_file = "metadata/key-spire-id"
         ctm_url = "https://<CipherTrustManager-instance>"
         username = "<uname>"
         password = "<pwd>"
        }
}
```

Details of the plugin data

| key               | type   | required | description                                                                  | default |
| :---------------- | :----- | :------- | :--------------------------------------------------------------------------- | :------ |
| key_metadata_file | string | Yes      | The directory to the spireID metadata, it will be used as the keys unique ID | None    |
| ctm_url           | string | Yes      | The address to your CipherTrustManager (local or remote)                     | None    |
| username          | string | Yes      | Username needed in exchange for a jwt token to access the CTM API            | None    |
| password          | string | Yes      | Password needed in exchange for a jwt token to access the CTM API            | None    |

#### Directory Configuration

For this plugin to work, all field must be valid and the directory containing the spire metadata must exists prior to running spire.

### How it Works

The plugin uses CipherTrust Key Manager to bootstrap the SPIRE Server identity and Signs SVIDs. The plugin operates as follows:

1. Fetches keys from CipherTrust Manager if any
2. Generates keys Pairs for SVIDs bundles (x509 and JWK)
3. Signs SVIDs when needed

### Building

To build this plugin on Linux, run `make build`.
The plugin binary will be placed in the `bin` folder

**Important note**
* `make build` will automatically parse the code to detect any anomaly.
* Prior runing the `make build`, install the [staticcheck](https://staticcheck.dev/docs/getting-started/), gofmt & go vet (go analysis tools) and the [goreportcard](https://github.com/gojp/goreportcard) tool.
* if no anomaly found, the binary and its hash will be generated in the `bin` folder.

```bash
gofmt...
Running staticcheck...
Running go vet...
Running goreportcard
goreportcard-cli -v
```

### Testing

- Functional plugin testing is located in `tests/ciphertrust_spire_plugin_test.go`
- Unit testing are located in `pkg/ciphertrustkms/tests`

Prior to the functional testing make sure you have a valid CipherTrust Manager instance running and update the following variables from `tests/ciphertrust_spire_plugin_test.go`:

```go
ctmService        = "https://<local/remote IP/name>"
username          = "user"
pwd               = "pwd"
 ```

Prior to the unit testing make sure you have a valid CipherTrust Manager instance running and update the following variables from `pkg/ciphertrustkms/tests/cihpertrustkms_test.go`:

```go
ctmService        = "https://<local/remote IP/name>"
username          = "user"
pwd               = "pwd"
 ```

## Contributing

If you are interested in contributing to the the CipherTrust Spire plugin project, start by reading the [Contributing guide](/CONTRIBUTING.md).

## License

Please read the [LICENSE](LICENSE) file.

## Security Vulnerability Reporting

If you believe you have identified a security vulnerability in this project, please send email to the project
team at security@opensource.thalesgroup.com, detailing the suspected issue and any methods you've found to reproduce it.

Please do NOT open an issue in the GitHub repository, as we'd prefer to keep vulnerability reports private until
we've had an opportunity to review and address them.

Please read the [SECURITY](SECURITY) file.
