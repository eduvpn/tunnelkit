//
//  OpenVPNTunnelProvider.swift
//  TunnelKit
//
//  Created by Davide De Rosa on 2/1/17.
//  Copyright (c) 2022 Davide De Rosa. All rights reserved.
//
//  https://github.com/passepartoutvpn
//
//  This file is part of TunnelKit.
//
//  TunnelKit is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  TunnelKit is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with TunnelKit.  If not, see <http://www.gnu.org/licenses/>.
//
//  This file incorporates work covered by the following copyright and
//  permission notice:
//
//      Copyright (c) 2018-Present Private Internet Access
//
//      Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
//
//      The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
//
//      THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

import NetworkExtension
import SwiftyBeaver
#if os(iOS)
import SystemConfiguration.CaptiveNetwork
#else
import CoreWLAN
#endif
import TunnelKitCore
import TunnelKitOpenVPNCore
import TunnelKitManager
import TunnelKitOpenVPNManager
import TunnelKitOpenVPNProtocol
import TunnelKitAppExtension
import CTunnelKitCore
import __TunnelKitUtils

private let log = SwiftyBeaver.self

/**
 Provides an all-in-one `NEPacketTunnelProvider` implementation for use in a
 Packet Tunnel Provider extension both on iOS and macOS.
 */
open class OpenVPNTunnelProvider: NEPacketTunnelProvider {

    private lazy var adapter = OpenVPNAdapter(with: self)

    // MARK: Tweaks
    
    /// An optional string describing host app version on tunnel start.
    public var appVersion: String? {
        didSet { adapter.appVersion = appVersion }
    }

    /// The log separator between sessions.
    public var logSeparator = "--- EOF ---"
    
    /// The maximum size of the log.
    public var maxLogSize = 20000
    
    /// The log level when `OpenVPNTunnelProvider.Configuration.shouldDebug` is enabled.
    public var debugLogLevel: SwiftyBeaver.Level? {
        didSet {
            if let debugLogLevel = debugLogLevel {
                adapter.debugLogLevel = debugLogLevel
            }
        }
    }
    
    /// The number of milliseconds after which a DNS resolution fails.
    public var dnsTimeout: Int? {
        didSet {
            if let dnsTimeout = dnsTimeout {
                adapter.dnsTimeout = dnsTimeout
            }
        }
    }
    
    /// The number of milliseconds after which the tunnel gives up on a connection attempt.
    public var socketTimeout: Int? {
        didSet {
            if let socketTimeout = socketTimeout {
                adapter.socketTimeout = socketTimeout
            }
        }
    }
    
    /// The number of milliseconds after which the tunnel is shut down forcibly.
    public var shutdownTimeout: Int? {
        didSet {
            if let shutdownTimeout = shutdownTimeout {
                adapter.shutdownTimeout = shutdownTimeout
            }
        }
    }
    
    /// The number of milliseconds after which a reconnection attempt is issued.
    public var reconnectionDelay: Int? {
        didSet {
            if let reconnectionDelay = reconnectionDelay {
                adapter.reconnectionDelay = reconnectionDelay
            }
        }
    }
    
    /// The number of milliseconds between data count updates. Set to 0 to disable updates (default).
    public var dataCountInterval = 0
    
    /// A list of public DNS servers to use as fallback when none are provided (defaults to CloudFlare).
    public var fallbackDNSServers: [String]? {
        didSet {
            if let fallbackDNSServers = fallbackDNSServers {
                adapter.fallbackDNSServers = fallbackDNSServers
            }
        }
    }

    private var isCountingData = false
    private var cfg: OpenVPN.ProviderConfiguration!

    open override func startTunnel(options: [String : NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {

        // required configuration
        do {
            guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol else {
                throw OpenVPNProviderConfigurationError.parameter(name: "protocolConfiguration")
            }
            guard let _ = tunnelProtocol.serverAddress else {
                throw OpenVPNProviderConfigurationError.parameter(name: "protocolConfiguration.serverAddress")
            }
            guard let providerConfiguration = tunnelProtocol.providerConfiguration else {
                throw OpenVPNProviderConfigurationError.parameter(name: "protocolConfiguration.providerConfiguration")
            }
            cfg = try fromDictionary(OpenVPN.ProviderConfiguration.self, providerConfiguration)
        } catch let e {
            var message: String?
            if let te = e as? OpenVPNProviderConfigurationError {
                switch te {
                case .parameter(let name):
                    message = "Tunnel configuration incomplete: \(name)"
                    
                default:
                    break
                }
            }
            NSLog(message ?? "Unexpected error in tunnel configuration: \(e)")
            completionHandler(e)
            return
        }

        // prepare for logging (append)
        configureLogging()

        // logging only ACTIVE from now on
        log.info("")
        log.info(logSeparator)
        log.info("")

        // override library configuration
        CoreConfiguration.masksPrivateData = cfg.masksPrivateData
        if let versionIdentifier = cfg.versionIdentifier {
            CoreConfiguration.versionIdentifier = versionIdentifier
        }

        // optional credentials
        let credentials: OpenVPN.Credentials?
        if let username = protocolConfiguration.username, let passwordReference = protocolConfiguration.passwordReference {
            guard let password = try? Keychain.password(forReference: passwordReference) else {
                completionHandler(OpenVPNProviderConfigurationError.credentials(details: "Keychain.password(forReference:)"))
                return
            }
            credentials = OpenVPN.Credentials(username, password)
        } else {
            credentials = nil
        }

        log.info("Starting tunnel...")
        cfg._appexSetLastError(nil)

        adapter.start(providerConfiguration: cfg, credentials: credentials) { [weak self] error in
            guard let self = self else { return }
            if error == nil {
                self.isCountingData = true
                self.refreshDataCount()
            }
            completionHandler(error)
        }
    }
    
    open override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        log.info("Stopping tunnel...")
        cfg._appexSetLastError(nil)
        
        adapter.stop { [weak self] in
            guard let self = self else { return }
            self.isCountingData = false
            self.refreshDataCount()
            completionHandler()
            self.forceExitOnMac()
        }
    }
    
    // MARK: Wake/Sleep (debugging placeholders)

    open override func wake() {
        log.info("Wake signal received")
        adapter.wake()
    }
    
    open override func sleep(completionHandler: @escaping () -> Void) {
        log.info("Sleep signal received")
        adapter.sleep(completionHandler: completionHandler)
    }
    
    private func refreshDataCount() {
        guard dataCountInterval > 0 else {
            return
        }
        adapter.tunnelQueue.schedule(after: .milliseconds(dataCountInterval)) { [weak self] in
            self?.refreshDataCount()
        }
        guard isCountingData, let dataCount = adapter.dataCount() else {
            cfg._appexSetDataCount(nil)
            return
        }
        cfg._appexSetDataCount(dataCount)
    }
}

extension OpenVPNTunnelProvider {
    // MARK: Logging
    
    private func configureLogging() {
        let logLevel: SwiftyBeaver.Level = (cfg.shouldDebug ? adapter.debugLogLevel : .info)
        let logFormat = cfg.debugLogFormat ?? "$Dyyyy-MM-dd HH:mm:ss.SSS$d $L $N.$F:$l - $M"

        if cfg.shouldDebug {
            let console = ConsoleDestination()
            console.useNSLog = true
            console.minLevel = logLevel
            console.format = logFormat
            log.addDestination(console)
        }

        let file = FileDestination(logFileURL: cfg._appexDebugLogURL)
        file.minLevel = logLevel
        file.format = logFormat
        file.logFileMaxSize = maxLogSize
        log.addDestination(file)

        // store path for clients
        cfg._appexSetDebugLogPath()
    }
}

extension OpenVPNTunnelProvider: OpenVPNAdapterDelegate {
    public func sessionWillStart() {
        cfg._appexSetServerConfiguration(nil)
        cfg._appexSetLastError(nil)
        refreshDataCount()
    }

    public func sessionDidStart(serverConfiguration: OpenVPN.Configuration) {
        cfg._appexSetServerConfiguration(serverConfiguration)
        refreshDataCount()
    }

    public func sessionDidStop(error: Error?) {
        cfg._appexSetServerConfiguration(nil)
        isCountingData = false
        refreshDataCount()
        cfg._appexSetLastError(unifiedError(from: error))
    }

    private func unifiedError(from error: Error?) -> OpenVPNProviderError? {
        guard let error = error else {
            return nil
        }
        if let te = error.openVPNErrorCode() {
            switch te {
            case .cryptoRandomGenerator, .cryptoAlgorithm:
                return .encryptionInitialization
                
            case .cryptoEncryption, .cryptoHMAC:
                return .encryptionData
                
            case .tlscaRead, .tlscaUse, .tlscaPeerVerification,
                    .tlsClientCertificateRead, .tlsClientCertificateUse,
                    .tlsClientKeyRead, .tlsClientKeyUse:
                return .tlsInitialization
                
            case .tlsServerCertificate, .tlsServerEKU, .tlsServerHost:
                return .tlsServerVerification
                
            case .tlsHandshake:
                return .tlsHandshake
                
            case .dataPathOverflow, .dataPathPeerIdMismatch:
                return .unexpectedReply
                
            case .dataPathCompression:
                return .serverCompression
                
            default:
                break
            }
        } else if let se = error as? OpenVPNError {
            switch se {
            case .negotiationTimeout, .pingTimeout, .staleSession:
                return .timeout
                
            case .badCredentials:
                return .authentication
                
            case .serverCompression:
                return .serverCompression
                
            case .failedLinkWrite:
                return .linkError
                
            case .noRouting:
                return .routing
                
            case .serverShutdown:
                return .serverShutdown

            default:
                return .unexpectedReply
            }
        }
        return error as? OpenVPNProviderError ?? .linkError
    }
}

private extension NEPacketTunnelProvider {
    func forceExitOnMac() {
        #if os(macOS)
        exit(0)
        #endif
    }
}
