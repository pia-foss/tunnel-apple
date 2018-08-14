[![PIA logo][pia-image]][pia-url]

# Private Internet Access

Private Internet Access is the world's leading consumer VPN service. At Private Internet Access we believe in unfettered access for all, and as a firm supporter of the open source ecosystem we have made the decision to open source our VPN clients. For more information about the PIA service, please visit our website [privateinternetaccess.com][pia-url] or check out the [Wiki][pia-wiki].

# Tunnel for Apple platforms

This library provides a simplified Swift/Obj-C implementation of the OpenVPN® protocol for the Apple platforms, while also taking advantage of the Private Internet Access [client patch customizations](https://www.privateinternetaccess.com/forum/discussion/9093/pia-openvpn-client-encryption-patch). The crypto layer is built on top of [OpenSSL][dep-openssl] 1.1.0h, which in turn enables support for a certain range of encryption and digest algorithms.

## Getting started

The client is known to work with [OpenVPN®][openvpn] 2.3+ servers. Key renegotiation and replay protection are also included, but full-fledged configuration files (.ovpn) are not currently supported.

- [x] Handshake and tunneling over UDP or TCP
- [x] Client-initiated renegotiation
- [x] Replay protection (hardcoded window)
- [x] Data encryption
    - AES-CBC (128 and 256 bit)
    - AES-GCM (128 and 256 bit)
- [x] HMAC digest
    - SHA-1
    - SHA-256
- [x] TLS CA validation
    - RSA (2048, 3072 and 4096 bit)
    - ECC (secp256r1, secp521r1, secp256k1)
    - Custom certificate

## Installation

### Requirements

- iOS 9.0+ / macOS 10.11+
- Xcode 9+ (Swift 4)
- Git (preinstalled with Xcode Command Line Tools)
- Ruby (preinstalled with macOS)
- [CocoaPods 1.5.0][dep-cocoapods]
- [jazzy][dep-jazzy] (optional, for documentation)

It's highly recommended to use the Git and Ruby packages provided by [Homebrew][dep-brew].

### CocoaPods

To use with CocoaPods just add this to your Podfile:

```ruby
pod 'PIATunnel'
```

### Testing

Download the library codebase locally:

    $ git clone https://github.com/pia-foss/tunnel-apple.git

Assuming you have a [working CocoaPods environment][dep-cocoapods], setting up the library workspace only requires installing the pod dependencies:

    $ pod install

After that, open `PIATunnel.xcworkspace` in Xcode and run the unit tests found in the `PIATunnelTests` target. A simple CMD+U while on `PIATunnel-iOS` should do that as well.

#### Demo

There is a `Demo` directory containing a simple app for testing the tunnel, called `BasicTunnel`. As usual, prepare for CocoaPods:

    $ pod install

then open `Demo.xcworkspace` and run the `BasicTunnel-iOS` target.

For the VPN to work properly, the `BasicTunnel` demo requires:

- _App Groups_ and _Keychain Sharing_ capabilities
- App IDs with _Packet Tunnel_ entitlements

both in the main app and the tunnel extension target.

In order to test connection to your own server rather than a PIA server, modify the file `Demo/BasicTunnel-[iOS|macOS]/ViewController.swift` and make sure to:

- Replace `.pia` with `.vanilla` in `builder.endpointProtocols`.
- Set `builder.handshake` to `.custom`.
- Set `builder.ca` to the PEM formatted certificate of your VPN server's CA.

Example:

    builder.endpointProtocols = [PIATunnelProvider.EndpointProtocol(.udp, 1194, .vanilla)]
    builder.handshake = .custom
    builder.ca = """
    -----BEGIN CERTIFICATE-----
    MIIFJDCC...
    -----END CERTIFICATE-----
    """

## Documentation

The library is split into two modules, in order to decouple the low-level protocol implementation from the platform-specific bridging, namely the [NetworkExtension][ne-home] VPN framework.

Full documentation of the public interface is available and can be generated with [jazzy][dep-jazzy]. After installing the jazzy Ruby gem with:

    $ gem install jazzy

enter the root directory of the repository and run:

    $ jazzy

The generated output is stored into the `docs` directory in HTML format.

### Core

Here you will find the low-level entities on top of which the connection is established. Code is mixed Swift and Obj-C, most of it is not exposed to consumers. The *Core* module depends on OpenSSL and is mostly platform-agnostic.

The entry point is the `SessionProxy` class. The networking layer is fully abstract and delegated externally with the use of opaque `IOInterface` (`LinkInterface` and `TunnelInterface`) and `SessionProxyDelegate` protocols.

### AppExtension

The goal of this module is packaging up a black box implementation of a [NEPacketTunnelProvider][ne-ptp], which is the essential part of a Packet Tunnel Provider app extension. You will find the main implementation in the `PIATunnelProvider` class.

Currently, the extension supports VPN over both [UDP][ne-udp] and [TCP][ne-tcp] sockets. A debug log snapshot is optionally maintained and shared to host apps via `UserDefaults` in a shared App Group.

## Contributing

By contributing to this project you are agreeing to the terms stated in the Contributor License Agreement (CLA) [here](/CLA.rst).

For more details please see [CONTRIBUTING](/CONTRIBUTING.md).

Issues and Pull Requests should use these templates: [ISSUE](/.github/ISSUE_TEMPLATE.md) and [PULL REQUEST](/.github/PULL_REQUEST_TEMPLATE.md).

## Authors

- Davide De Rosa - [keeshux](https://github.com/keeshux)
- Steve

## License

This project is licensed under the [MIT (Expat) license](https://choosealicense.com/licenses/mit/), which can be found [here](/LICENSE).

## Acknowledgements

- SwiftyBeaver - © 2015 Sebastian Kreutzberger

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. ([https://www.openssl.org/][dep-openssl])

© 2002-2018 OpenVPN Inc. - OpenVPN is a registered trademark of OpenVPN Inc.

[pia-image]: https://www.privateinternetaccess.com/assets/PIALogo2x-0d1e1094ac909ea4c93df06e2da3db4ee8a73d8b2770f0f7d768a8603c62a82f.png
[pia-url]: https://www.privateinternetaccess.com/
[pia-wiki]: https://en.wikipedia.org/wiki/Private_Internet_Access

[openvpn]: https://openvpn.net/index.php/open-source/overview.html
[dep-cocoapods]: https://guides.cocoapods.org/using/getting-started.html
[dep-jazzy]: https://github.com/realm/jazzy
[dep-brew]: https://brew.sh/
[dep-openssl]: https://www.openssl.org/

[ne-home]: https://developer.apple.com/documentation/networkextension
[ne-ptp]: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
[ne-udp]: https://developer.apple.com/documentation/networkextension/nwudpsession
[ne-tcp]: https://developer.apple.com/documentation/networkextension/nwtcpconnection
