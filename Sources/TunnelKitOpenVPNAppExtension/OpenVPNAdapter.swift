//
//  OpenVPNAdapter.swift
//  TunnelKit
//
//  Created by Roopesh Chander on 11/16/22.
//  Copyright (c) 2022 Roopesh Chander. All rights reserved.
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

import Foundation
import NetworkExtension
import SwiftyBeaver
/*
#if os(iOS)
import SystemConfiguration.CaptiveNetwork
#else
import CoreWLAN
#endif
 */

import TunnelKitCore
import TunnelKitOpenVPNCore
import TunnelKitManager
import TunnelKitOpenVPNManager
import TunnelKitOpenVPNProtocol
import TunnelKitAppExtension
import CTunnelKitCore
import __TunnelKitUtils

private let log = SwiftyBeaver.self

public protocol OpenVPNAdapterDelegate: AnyObject {
    func sessionWillStart()
    func sessionDidStart(serverConfiguration: OpenVPN.Configuration)
    func sessionDidStop(error: Error?)
}

public class OpenVPNAdapter {

    /// Packet tunnel provider.
    private weak var packetTunnelProvider: NEPacketTunnelProvider?

    // Delegate
    public weak var delegate: OpenVPNAdapterDelegate?

    /// An optional string describing host app version on tunnel start.
    public var appVersion: String?

    /// The log level when `OpenVPNTunnelProvider.Configuration.shouldDebug` is enabled.
    public var debugLogLevel: SwiftyBeaver.Level = .debug

    /// The number of milliseconds after which a DNS resolution fails.
    public var dnsTimeout = 3000

    /// The number of milliseconds after which the tunnel gives up on a connection attempt.
    public var socketTimeout = 5000

    /// The number of milliseconds after which the tunnel is shut down forcibly.
    public var shutdownTimeout = 2000

    /// The number of milliseconds after which a reconnection attempt is issued.
    public var reconnectionDelay = 1000

    /// The number of milliseconds between data count updates. Set to 0 to disable updates (default).
    public var dataCountInterval = 0

    /// A list of public DNS servers to use as fallback when none are provided (defaults to CloudFlare).
    public var fallbackDNSServers = [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001"
    ]

    /// A handler to call if AUTH_FAIL occurs even after retrying without local TLS options.
    /// If this is set, it's called and the tunnel is not cancelled.
    /// If this is not set, the tunnel is cancelled.
    public var authFailShutdownHandler: (() -> Void)?


    /// A handler to call when the adapter needs to flush the log to disk.
    /// We're forced do this ugly thing because in SwiftyBeaver
    /// BaseDestination.flush() is not open, and not overrideable.
    public var flushLogHandler: (() -> Void)?

    // MARK: Constants

    public let tunnelQueue = DispatchQueue(label: OpenVPNTunnelProvider.description(), qos: .utility)

    private let prngSeedLength = 64

    private var cachesURL: URL {
        let appGroup = cfg.appGroup
        guard let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) else {
            fatalError("No access to app group: \(appGroup)")
        }
        return containerURL.appendingPathComponent("Library/Caches/")
    }

    // MARK: Tunnel configuration

    private var cfg: OpenVPN.ProviderConfiguration!

    private var strategy: ConnectionStrategy!

    // MARK: Internal state

    private var session: OpenVPNSession?

    private var socket: GenericSocket?

    private var pendingStartHandler: ((Error?) -> Void)?

    private var pendingStopHandler: (() -> Void)?

    private var pendingPauseHandler: (() -> Void)?

    private var shouldReconnect = false

    private var reasserting: Bool  = false {
        didSet {
            log.debug("Reasserting flag \(reasserting ? "set" : "cleared")")
            self.packetTunnelProvider?.reasserting = reasserting
        }
    }

    // MARK: NWPathMonitor usage

    private var pathMonitor: AnyObject?

    public init(with packetTunnelProvider: NEPacketTunnelProvider) {
        self.packetTunnelProvider = packetTunnelProvider
    }

    deinit {
        (pathMonitor as? NWPathMonitor)?.cancel()
    }

    /// Start the tunnel
    ///
    /// Initializes the session and starts the tunnel

    public func start(providerConfiguration: OpenVPN.ProviderConfiguration,
                      credentials: OpenVPN.Credentials?,
                      completionHandler: @escaping (Error?) -> Void) {

        cfg = providerConfiguration

        guard OpenVPN.prepareRandomNumberGenerator(seedLength: prngSeedLength) else {
            completionHandler(OpenVPNProviderConfigurationError.prngInitialization)
            return
        }

        if let appVersion = appVersion {
            log.info("App version: \(appVersion)")
        }
        cfg.print()

        // prepare to pick endpoints
        strategy = ConnectionStrategy(configuration: cfg.configuration)

        let session: OpenVPNSession
        do {
            session = try OpenVPNSession(queue: tunnelQueue, configuration: cfg.configuration, cachesURL: cachesURL)
        } catch let e {
            completionHandler(e)
            return
        }
        session.credentials = credentials
        session.delegate = self
        self.session = session

        logCurrentSSID()

        pendingStartHandler = completionHandler
        tunnelQueue.sync {
            self.connectTunnel()
        }
    }

    /// Stops the tunnel
    ///
    /// Sends exit notification, then shuts down the session and clears cached certificates

    public func stop(completionHandler: @escaping () -> Void) {
        pendingStartHandler = nil

        guard let session = session else {
            flushLog()
            completionHandler()
            return
        }

        pendingStopHandler = completionHandler
        tunnelQueue.schedule(after: .milliseconds(shutdownTimeout)) { [weak self] in
            guard let weakSelf = self else {
                return
            }
            guard let pendingHandler = weakSelf.pendingStopHandler else {
                return
            }
            log.warning("Tunnel not responding after \(weakSelf.shutdownTimeout) milliseconds, forcing stop")
            weakSelf.flushLog()
            pendingHandler()
        }
        tunnelQueue.sync {
            session.shutdown(error: nil)
        }
    }

    /// Pauses the tunnel for resuming later
    ///
    /// Sends exit notification, and in parallel, shuts down the socket

    public func pause(completionHandler: @escaping () -> Void) {
        if let socket = socket, !socket.isShutdown {
            log.debug("Shutting down socket")
            session?.sendExitNotificationIfApplicable(completion: nil)
            socket.shutdown()
            pendingPauseHandler = completionHandler
        } else {
            completionHandler()
        }
    }

    /// Resumes a paused tunnel

    public func resume() {
        self.connectTunnel()
    }
}

// MARK: Querying

extension OpenVPNAdapter {
    public func dataCount() -> DataCount? {
        return session?.dataCount()
    }

    public func serverConfiguration() -> OpenVPN.Configuration? {
        return session?.serverConfiguration() as? OpenVPN.Configuration
    }
}

private extension OpenVPNAdapter {
    // MARK: Connection (tunnel queue)

    private func connectTunnel(upgradedSocket: GenericSocket? = nil) {
        log.info("Creating link session")

        // reuse upgraded socket
        if let upgradedSocket = upgradedSocket, !upgradedSocket.isShutdown {
            log.debug("Socket follows a path upgrade")
            connectTunnel(via: upgradedSocket)
            return
        }

        guard let packetTunnelProvider = self.packetTunnelProvider else {
            log.debug("Missing packet tunnel provider")
            return
        }

        strategy.createSocket(from: packetTunnelProvider, timeout: dnsTimeout, queue: tunnelQueue) {
            switch $0 {
            case .success(let socket):
                self.connectTunnel(via: socket)

            case .failure(let error):
                if case .dnsFailure = error {
                    self.tunnelQueue.async {
                        self.strategy.tryNextEndpoint()
                        self.connectTunnel()
                    }
                    return
                }
                self.disposeTunnel(error: error)
            }
        }
    }

    private func connectTunnel(via socket: GenericSocket) {
        log.info("Will connect to \(socket)")
        log.debug("Socket type is \(type(of: socket))")
        self.socket = socket
        self.socket?.delegate = self
        self.socket?.observe(queue: tunnelQueue, activeTimeout: socketTimeout)
    }

    private func finishTunnelDisconnection(error: Error?) {
        if let session = session, !(shouldReconnect && session.canRebindLink()) {
            session.cleanup()
        }

        socket?.delegate = nil
        socket?.unobserve()
        socket = nil

        if let error = error {
            log.error("Tunnel did stop (error: \(error))")
        } else {
            log.info("Tunnel did stop on request")
        }
    }

    private func disposeTunnel(error: Error?) {
        flushLog()

        // failed to start
        if pendingStartHandler != nil {

            //
            // CAUTION
            //
            // passing nil to this callback will result in an extremely undesired situation,
            // because NetworkExtension would interpret it as "successfully connected to VPN"
            //
            // if we end up here disposing the tunnel with a pending start handled, we are
            // 100% sure that something wrong happened while starting the tunnel. in such
            // case, here we then must also make sure that an error object is ALWAYS
            // provided, so we do this with optional fallback to .socketActivity
            //
            // socketActivity makes sense, given that any other error would normally come
            // from OpenVPN.stopError. other paths to disposeTunnel() are only coming
            // from stopTunnel(), in which case we don't need to feed an error parameter to
            // the stop completion handler
            //
            pendingStartHandler?(error ?? OpenVPNProviderError.socketActivity)
            pendingStartHandler = nil
        }
        // stopped intentionally
        else if pendingStopHandler != nil {
            pendingStopHandler?()
            pendingStopHandler = nil
        }
        // stopped externally, unrecoverable
        else {
            self.packetTunnelProvider?.cancelTunnelWithError(error)
        }
    }
}

@available(macOS 10.14, iOS 12.0, *)
extension Network.NWPath {
        var isValid: Bool {
        guard status == .satisfied else { return false }
        guard let primaryInterface = availableInterfaces.first else { return false }
        if primaryInterface.type == .other && primaryInterface.name.hasPrefix("u") {
            return false
        }
        return true
    }
}

extension OpenVPNAdapter: GenericSocketDelegate {

    // MARK: GenericSocketDelegate (tunnel queue)

    public func socketDidTimeout(_ socket: GenericSocket) {
        log.debug("Socket timed out waiting for activity, cancelling...")
        shouldReconnect = true
        socket.shutdown()

        // fallback: TCP connection timeout suggests falling back
        if let _ = socket as? NETCPSocket {
            guard tryNextEndpoint() else {
                // disposeTunnel
                return
            }
        }
    }

    public func socketDidBecomeActive(_ socket: GenericSocket) {
        guard let session = session, let producer = socket as? LinkProducer else {
            return
        }
        if session.canRebindLink() {
            session.rebindLink(producer.link(xorMask: cfg.configuration.xorMask))
            reasserting = false
        } else {
            session.setLink(producer.link(xorMask: cfg.configuration.xorMask))
        }
    }

    public func socket(_ socket: GenericSocket, didShutdownWithFailure failure: Bool) {
        guard let session = session else {
            return
        }

        var shutdownError: Error?
        let didTimeoutNegotiation: Bool
        var upgradedSocket: GenericSocket?

        // look for error causing shutdown
        shutdownError = session.stopError
        if failure && (shutdownError == nil) {
            shutdownError = OpenVPNProviderError.linkError
        }
        didTimeoutNegotiation = (shutdownError as? OpenVPNError == .negotiationTimeout)

        // only try upgrade on network errors
        if shutdownError as? OpenVPNError == nil {
            upgradedSocket = socket.upgraded()
        }

        // clean up
        finishTunnelDisconnection(error: shutdownError)

        if let pendingPauseHandler = self.pendingPauseHandler {
            // If we shutdown the tunnel because of shutdownTunnelWithoutExitingProcess,
            // just call the completion handler. Don't exit the process.
            log.debug("Calling pending shutdown handler")
            self.pendingPauseHandler = nil
            pendingPauseHandler()
            return
        }

        // fallback: UDP is connection-less, treat negotiation timeout as socket timeout
        if didTimeoutNegotiation {
            guard tryNextEndpoint() else {
                // If there are no more endpoints, cancel the tunnel
                log.debug("Disposing tunnel")
                disposeTunnel(error: shutdownError)
                return
            }
        }

        // reconnect?
        if shouldReconnect {
            log.debug("Disconnection is recoverable, tunnel will reconnect in \(reconnectionDelay) milliseconds...")
            tunnelQueue.schedule(after: .milliseconds(reconnectionDelay)) {

                // give up if shouldReconnect cleared in the meantime
                guard self.shouldReconnect else {
                    log.warning("Reconnection flag was cleared in the meantime")
                    self.disposeTunnel(error: shutdownError)
                    return
                }

                log.debug("Tunnel is about to reconnect...")
                self.reasserting = true
                self.connectTunnel(upgradedSocket: upgradedSocket)
            }
            return
        }

        let isAuthFailure = (shutdownError as? OpenVPNError == .authenticationFailure)
        if isAuthFailure && !shouldReconnect {
            if let authFailShutdownHandler = self.authFailShutdownHandler {
                log.debug("Calling authFailShutdownHandler")
                authFailShutdownHandler()
                return
            }
        }

        // shut down
        log.debug("Disposing tunnel")
        disposeTunnel(error: shutdownError)
    }

    public func socketHasBetterPath(_ socket: GenericSocket) {
        if #available(macOS 10.14, iOS 12.0, *) {
            if let pathMonitor = self.pathMonitor as? NWPathMonitor {
                log.debug("Socket has better path. Path status: \(pathMonitor.currentPath.status). Interfaces: \(pathMonitor.currentPath.availableInterfaces)")
                if pathMonitor.currentPath.isValid {
                    log.debug("Path computed to be valid")
                } else {
                    log.debug("Path computed to be invalid -- possibly spurious better path call")
                }
            }
        }
        log.debug("Stopping tunnel due to a new better path")
        logCurrentSSID()
        session?.reconnect(error: OpenVPNProviderError.networkChanged)
    }
}

extension OpenVPNAdapter: OpenVPNSessionDelegate {

    // MARK: OpenVPNSessionDelegate (tunnel queue)

    public func sessionDidStart(_ session: OpenVPNSession, remoteAddress: String, options: OpenVPN.Configuration) {
        log.info("Session did start")

        log.info("Returned ifconfig parameters:")
        log.info("\tRemote: \(remoteAddress.maskedDescription)")
        log.info("\tIPv4: \(options.ipv4?.description ?? "not configured")")
        log.info("\tIPv6: \(options.ipv6?.description ?? "not configured")")
        if let routingPolicies = options.routingPolicies {
            log.info("\tGateway: \(routingPolicies.map { $0.rawValue })")
        } else {
            log.info("\tGateway: not configured")
        }
        if let dnsServers = options.dnsServers, !dnsServers.isEmpty {
            log.info("\tDNS: \(dnsServers.map { $0.maskedDescription })")
        } else {
            log.info("\tDNS: not configured")
        }
        if let searchDomains = options.searchDomains, !searchDomains.isEmpty {
            log.info("\tSearch domains: \(searchDomains.maskedDescription)")
        } else {
            log.info("\tSearch domains: not configured")
        }

        if options.httpProxy != nil || options.httpsProxy != nil || options.proxyAutoConfigurationURL != nil {
            log.info("\tProxy:")
            if let proxy = options.httpProxy {
                log.info("\t\tHTTP: \(proxy.maskedDescription)")
            }
            if let proxy = options.httpsProxy {
                log.info("\t\tHTTPS: \(proxy.maskedDescription)")
            }
            if let pacURL = options.proxyAutoConfigurationURL {
                log.info("\t\tPAC: \(pacURL)")
            }
            if let bypass = options.proxyBypassDomains {
                log.info("\t\tBypass domains: \(bypass.maskedDescription)")
            }
        }

        if let serverConfig = serverConfiguration() {
            delegate?.sessionDidStart(serverConfiguration: serverConfig)
        }

        bringNetworkUp(remoteAddress: remoteAddress, localOptions: session.configuration, options: options) { (error) in

            // FIXME: XPC queue

            self.reasserting = false

            if let error = error {
                log.error("Failed to configure tunnel: \(error)")
                self.pendingStartHandler?(error)
                self.pendingStartHandler = nil
                return
            }

            log.info("Tunnel interface is now UP")

            guard let packetTunnelProvider = self.packetTunnelProvider else {
                log.debug("Missing packet tunnel provider")
                return
            }

            session.setTunnel(tunnel: NETunnelInterface(impl: packetTunnelProvider.packetFlow))

            if #available(macOS 10.14, iOS 12.0, *) {
                log.debug("Setting up path monitor")
                let pathMonitor = NWPathMonitor()
                pathMonitor.start(queue: self.tunnelQueue)
                self.pathMonitor = pathMonitor
            }

            self.pendingStartHandler?(nil)
            self.pendingStartHandler = nil
        }
    }

    public func sessionDidStop(_: OpenVPNSession, withError error: Error?, shouldReconnect: Bool) {

        if let error = error {
            log.error("Session did stop with error: \(error)")
        } else {
            log.info("Session did stop")
        }
        delegate?.sessionDidStop(error: error)

        self.shouldReconnect = shouldReconnect
        socket?.shutdown()
    }

    private func bringNetworkUp(remoteAddress: String, localOptions: OpenVPN.Configuration, options: OpenVPN.Configuration, completionHandler: @escaping (Error?) -> Void) {
        let routingPolicies = localOptions.routingPolicies ?? options.routingPolicies
        let isIPv4Gateway = routingPolicies?.contains(.IPv4) ?? false
        let isIPv6Gateway = routingPolicies?.contains(.IPv6) ?? false
        let isGateway = isIPv4Gateway || isIPv6Gateway

        var ipv4Settings: NEIPv4Settings?
        if let ipv4 = options.ipv4 {
            var routes: [NEIPv4Route] = []
            var excludedRoutes: [NEIPv4Route] = []

            // route all traffic to VPN?
            if isIPv4Gateway {
                let defaultRoute = NEIPv4Route.default()
                defaultRoute.gatewayAddress = ipv4.defaultGateway
                routes.append(defaultRoute)
//                for network in ["0.0.0.0", "128.0.0.0"] {
//                    let route = NEIPv4Route(destinationAddress: network, subnetMask: "128.0.0.0")
//                    route.gatewayAddress = ipv4.defaultGateway
//                    routes.append(route)
//                }
                log.info("Routing.IPv4: Setting default gateway to \(ipv4.defaultGateway.maskedDescription)")
            }

            for r in ipv4.routes {
                let ipv4Route = NEIPv4Route(destinationAddress: r.destination, subnetMask: r.mask)
                ipv4Route.gatewayAddress = r.gateway
                routes.append(ipv4Route)
                log.info("Routing.IPv4: Adding route \(r.destination.maskedDescription)/\(r.mask) -> \(r.gateway ?? "-")")
            }

            for r in ipv4.excludedRoutes {
                let ipv4Route = NEIPv4Route(destinationAddress: r.destination, subnetMask: r.mask)
                ipv4Route.gatewayAddress = nil
                excludedRoutes.append(ipv4Route)
                log.info("Routing.IPv4: Excluding route \(r.destination.maskedDescription)/\(r.mask)")
            }

            ipv4Settings = NEIPv4Settings(addresses: [ipv4.address], subnetMasks: [ipv4.addressMask])
            ipv4Settings?.includedRoutes = routes
            ipv4Settings?.excludedRoutes = excludedRoutes
        }

        var ipv6Settings: NEIPv6Settings?
        if let ipv6 = options.ipv6 {
            var routes: [NEIPv6Route] = []
            var excludedRoutes: [NEIPv6Route] = []

            // route all traffic to VPN?
            if isIPv6Gateway {
                let defaultRoute = NEIPv6Route.default()
                defaultRoute.gatewayAddress = ipv6.defaultGateway
                routes.append(defaultRoute)
//                for network in ["2000::", "3000::"] {
//                    let route = NEIPv6Route(destinationAddress: network, networkPrefixLength: 4)
//                    route.gatewayAddress = ipv6.defaultGateway
//                    routes.append(route)
//                }
                log.info("Routing.IPv6: Setting default gateway to \(ipv6.defaultGateway.maskedDescription)")
            }

            for r in ipv6.routes {
                let ipv6Route = NEIPv6Route(destinationAddress: r.destination, networkPrefixLength: r.prefixLength as NSNumber)
                ipv6Route.gatewayAddress = r.gateway
                routes.append(ipv6Route)
                log.info("Routing.IPv6: Adding route \(r.destination.maskedDescription)/\(r.prefixLength) -> \(r.gateway ?? "-")")
            }

            for r in ipv6.excludedRoutes {
                let ipv6Route = NEIPv6Route(destinationAddress: r.destination, networkPrefixLength: r.prefixLength as NSNumber)
                ipv6Route.gatewayAddress = nil
                excludedRoutes.append(ipv6Route)
                log.info("Routing.IPv6: Excluding route \(r.destination.maskedDescription)/\(r.prefixLength)")
            }

            ipv6Settings = NEIPv6Settings(addresses: [ipv6.address], networkPrefixLengths: [ipv6.addressPrefixLength as NSNumber])
            ipv6Settings?.includedRoutes = routes
            ipv6Settings?.excludedRoutes = excludedRoutes
        }

        // shut down if default gateway is not attainable
        var hasGateway = false
        if isIPv4Gateway && (ipv4Settings != nil) {
            hasGateway = true
        }
        if isIPv6Gateway && (ipv6Settings != nil) {
            hasGateway = true
        }
        guard !isGateway || hasGateway else {
            session?.shutdown(error: OpenVPNProviderError.gatewayUnattainable)
            return
        }

        var dnsSettings: NEDNSSettings?
        if cfg.configuration.isDNSEnabled ?? true {
            var dnsServers: [String] = []
            if #available(iOS 14, macOS 11, *) {
                switch cfg.configuration.dnsProtocol {
                case .https:
                    dnsServers = cfg.configuration.dnsServers ?? []
                    guard let serverURL = cfg.configuration.dnsHTTPSURL else {
                        break
                    }
                    let specific = NEDNSOverHTTPSSettings(servers: dnsServers)
                    specific.serverURL = serverURL
                    dnsSettings = specific
                    log.info("DNS over HTTPS: Using servers \(dnsServers.maskedDescription)")
                    log.info("\tHTTPS URL: \(serverURL.maskedDescription)")

                case .tls:
                    dnsServers = cfg.configuration.dnsServers ?? []
                    guard let serverName = cfg.configuration.dnsTLSServerName else {
                        break
                    }
                    let specific = NEDNSOverTLSSettings(servers: dnsServers)
                    specific.serverName = serverName
                    dnsSettings = specific
                    log.info("DNS over TLS: Using servers \(dnsServers.maskedDescription)")
                    log.info("\tTLS server name: \(serverName.maskedDescription)")

                default:
                    break
                }
            }

            // fall back
            if dnsSettings == nil {
                dnsServers = []
                if let servers = cfg.configuration.dnsServers,
                   !servers.isEmpty {
                    dnsServers = servers
                } else if let servers = options.dnsServers {
                    dnsServers = servers
                }
                if !dnsServers.isEmpty {
                    log.info("DNS: Using servers \(dnsServers.maskedDescription)")
                    dnsSettings = NEDNSSettings(servers: dnsServers)
                } else {
    //                log.warning("DNS: No servers provided, using fall-back servers: \(fallbackDNSServers.maskedDescription)")
    //                dnsSettings = NEDNSSettings(servers: fallbackDNSServers)
                    log.warning("DNS: No settings provided, using current network settings")
                }
            }

            // "hack" for split DNS (i.e. use VPN only for DNS)
            if !isGateway {
                dnsSettings?.matchDomains = [""]
            }
            
            if let searchDomains = cfg.configuration.searchDomains ?? options.searchDomains {
                log.info("DNS: Using search domains \(searchDomains.maskedDescription)")
                dnsSettings?.domainName = searchDomains.first
                dnsSettings?.searchDomains = searchDomains
                if !isGateway {
                    dnsSettings?.matchDomains = dnsSettings?.searchDomains
                }
            }
            
            // add direct routes to DNS servers
            if !isGateway {
                for server in dnsServers {
                    if server.contains(":") {
                        ipv6Settings?.includedRoutes?.insert(NEIPv6Route(destinationAddress: server, networkPrefixLength: 128), at: 0)
                    } else {
                        ipv4Settings?.includedRoutes?.insert(NEIPv4Route(destinationAddress: server, subnetMask: "255.255.255.255"), at: 0)
                    }
                }
            }
        }
        
        var proxySettings: NEProxySettings?
        if cfg.configuration.isProxyEnabled ?? true {
            if let httpsProxy = cfg.configuration.httpsProxy ?? options.httpsProxy {
                proxySettings = NEProxySettings()
                proxySettings?.httpsServer = httpsProxy.neProxy()
                proxySettings?.httpsEnabled = true
                log.info("Routing: Setting HTTPS proxy \(httpsProxy.address.maskedDescription):\(httpsProxy.port)")
            }
            if let httpProxy = cfg.configuration.httpProxy ?? options.httpProxy {
                if proxySettings == nil {
                    proxySettings = NEProxySettings()
                }
                proxySettings?.httpServer = httpProxy.neProxy()
                proxySettings?.httpEnabled = true
                log.info("Routing: Setting HTTP proxy \(httpProxy.address.maskedDescription):\(httpProxy.port)")
            }
            if let pacURL = cfg.configuration.proxyAutoConfigurationURL ?? options.proxyAutoConfigurationURL {
                if proxySettings == nil {
                    proxySettings = NEProxySettings()
                }
                proxySettings?.proxyAutoConfigurationURL = pacURL
                proxySettings?.autoProxyConfigurationEnabled = true
                log.info("Routing: Setting PAC \(pacURL.maskedDescription)")
            }

            // only set if there is a proxy (proxySettings set to non-nil above)
            if let bypass = cfg.configuration.proxyBypassDomains ?? options.proxyBypassDomains {
                proxySettings?.exceptionList = bypass
                log.info("Routing: Setting proxy by-pass list: \(bypass.maskedDescription)")
            }
        }

        // block LAN if desired
        if routingPolicies?.contains(.blockLocal) ?? false {
            let table = RoutingTable()
            if isIPv4Gateway,
                let gateway = table.defaultGateway4()?.gateway(),
                let route = table.broadestRoute4(matchingDestination: gateway) {

                log.info("Block local: Broadest route4 matching default gateway \(gateway) is \(route)")

                route.partitioned()?.forEach {
                    let destination = $0.network()
                    guard let netmask = $0.networkMask() else {
                        return
                    }
                    
                    log.info("Block local: Suppressing IPv4 route \(destination)/\($0.prefix())")
                    
                    let included = NEIPv4Route(destinationAddress: destination, subnetMask: netmask)
                    included.gatewayAddress = options.ipv4?.defaultGateway
                    ipv4Settings?.includedRoutes?.append(included)
                }
            }
            if isIPv6Gateway,
                let gateway = table.defaultGateway6()?.gateway(),
                let route = table.broadestRoute6(matchingDestination: gateway) {

                log.info("Block local: Broadest route6 matching default gateway \(gateway) is \(route)")

                route.partitioned()?.forEach {
                    let destination = $0.network()
                    let prefix = $0.prefix()
                    
                    log.info("Block local: Suppressing IPv6 route \(destination)/\($0.prefix())")

                    let included = NEIPv6Route(destinationAddress: destination, networkPrefixLength: prefix as NSNumber)
                    included.gatewayAddress = options.ipv6?.defaultGateway
                    ipv6Settings?.includedRoutes?.append(included)
                }
            }
        }
        
        let newSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteAddress)
        newSettings.ipv4Settings = ipv4Settings
        newSettings.ipv6Settings = ipv6Settings
        newSettings.dnsSettings = dnsSettings
        newSettings.proxySettings = proxySettings
        if let mtu = cfg.configuration.mtu, mtu > 0 {
            newSettings.mtu = NSNumber(value: mtu)
        }

        self.packetTunnelProvider?.setTunnelNetworkSettings(
            newSettings, completionHandler: completionHandler)
    }
}

extension OpenVPNAdapter {
    private func tryNextEndpoint() -> Bool {
        guard strategy.tryNextEndpoint() else {
            disposeTunnel(error: OpenVPNProviderError.exhaustedEndpoints)
            return false
        }
        return true
    }

    private func flushLog() {
        if let flushLogHandler = self.flushLogHandler {
            log.debug("Flushing log...")
            flushLogHandler()
        } else {
            log.debug("No flush log handler is set")
        }
    }

    private func logCurrentSSID() {
        InterfaceObserver.fetchCurrentSSID {
            if let ssid = $0 {
                log.debug("Current SSID: '\(ssid.maskedDescription)'")
            } else {
                log.debug("Current SSID: none (disconnected from WiFi)")
            }
        }
    }

//    private func anyPointer(_ object: Any?) -> UnsafeMutableRawPointer {
//        let anyObject = object as AnyObject
//        return Unmanaged<AnyObject>.passUnretained(anyObject).toOpaque()
//    }

}

private extension Proxy {
    func neProxy() -> NEProxyServer {
        return NEProxyServer(address: address, port: Int(port))
    }
}
