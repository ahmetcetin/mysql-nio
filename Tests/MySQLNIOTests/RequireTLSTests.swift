import Logging
@testable import MySQLNIO
import NIOCore
import NIOEmbedded
import NIOPosix
import NIOSSL
import Testing

@Suite("requireTLS: no handshake response unless TLS is set up")
struct RequireTLSTests {
    /// A server (or a man in the middle) that leaves CLIENT_SSL out of its greeting must not get the user name or the
    /// auth response in plaintext when the caller asked for TLS.
    @Test func serverWithoutSSLFailsAndNothingIsWritten() throws {
        let rig = try Rig(tls: .makeClientConfiguration(), requireTLS: true)
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(ssl: false), sequence: 0))
        #expect(rig.failure as? MySQLError == .secureConnectionRequired)
        let written = try rig.written()
        #expect(written.map(\.payload.count) == [], "sizes of the packets the client wrote")
    }

    /// With no TLS configuration there is no way to set up TLS, even when the server offers it.
    @Test func noTLSConfigurationFailsAndNothingIsWritten() throws {
        let rig = try Rig(tls: nil, requireTLS: true)
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(ssl: true), sequence: 0))
        #expect(rig.failure as? MySQLError == .secureConnectionRequired)
        let written = try rig.written()
        #expect(written.map(\.payload.count) == [], "sizes of the packets the client wrote")
    }

    /// When the server offers SSL, `requireTLS` changes nothing: the first packet is the SSLRequest.
    @Test func serverWithSSLGetsTheSSLRequest() throws {
        let rig = try Rig(tls: .makeClientConfiguration(), requireTLS: true)
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(ssl: true), sequence: 0))
        #expect(rig.outcome.result == nil, "the handshake must not fail")
        // Only the first write: after it the TLS handler sits in front and writes its ClientHello.
        let request = try #require(try rig.firstWrittenPacket())
        #expect(request.sequence == 1)
        #expect(request.payload.count == 32)
        let capabilities = request.payload.prefix(4).enumerated().reduce(UInt32(0)) { $0 | UInt32($1.element) << (8 * $1.offset) }
        #expect(capabilities & Wire.clientSSL != 0)
    }

    /// The default is unchanged: without `requireTLS` a server without SSL still gets a plaintext handshake response.
    @Test func defaultStillSendsTheHandshakeResponseInPlaintext() throws {
        let rig = try Rig(tls: .makeClientConfiguration(), requireTLS: false)
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(ssl: false), sequence: 0))
        #expect(rig.outcome.result == nil, "the handshake must not fail")
        let response = try #require(try rig.written().first)
        #expect(response.sequence == 1)
        #expect(Array(response.payload[32..<38]) == Array("tester".utf8))
        #expect(Wire.authResponse(inHandshakeResponse: response.payload)?.count == 32)
    }

    /// The parameter reaches the handler through the public `connect`: against a loopback server whose greeting has
    /// no CLIENT_SSL, `connect(requireTLS: true)` fails, and all the server receives is the COM_QUIT that closing the
    /// connection sends: no handshake response, no SSLRequest.
    @Test func connectWithRequireTLSFailsWithoutAHandshakeResponse() async throws {
        let recorder = GreetingServer.Received()
        let group = MultiThreadedEventLoopGroup.singleton
        let server = try await ServerBootstrap(group: group)
            .childChannelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(GreetingServer(
                        bytes: Wire.frame(Wire.greeting(ssl: false), sequence: 0),
                        received: recorder
                    ))
                }
            }
            .bind(host: "127.0.0.1", port: 0)
            .get()
        defer { server.close(promise: nil) }

        // The result is kept on the client's event loop and read only after the server saw the connection close (the
        // client closes it on failure, the server after two seconds), so the test ends even if `connect` never does.
        let eventLoop = group.next()
        let result = ResultBox()
        MySQLConnection.connect(
            to: try #require(server.localAddress),
            username: "tester",
            database: "test",
            password: "s3cret",
            tlsConfiguration: .makeClientConfiguration(),
            requireTLS: true,
            on: eventLoop
        ).whenComplete { result.value = $0 }
        try await recorder.closed.futureResult.get()
        let outcome = try await eventLoop.submit { result.value }.get()

        #expect(recorder.bytes == Wire.frame([0x01], sequence: 0), "only COM_QUIT may reach the server")
        switch outcome {
        case .failure(let error): #expect(error as? MySQLError == .secureConnectionRequired)
        case .success(let connection):
            Issue.record("connected without TLS")
            try await connection.close().get()
        case nil: Issue.record("connect neither failed nor succeeded before the connection closed")
        }
    }
}

private final class ResultBox: @unchecked Sendable {
    var value: Result<MySQLConnection, any Error>?
}

/// A server that writes a canned greeting on connect, keeps what the client sends, and gives up after two seconds.
private final class GreetingServer: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias OutboundOut = ByteBuffer

    final class Received: @unchecked Sendable {
        let closed = MultiThreadedEventLoopGroup.singleton.any().makePromise(of: Void.self)
        var bytes: [UInt8] = []
    }

    let bytes: [UInt8]
    let received: Received
    init(bytes: [UInt8], received: Received) {
        self.bytes = bytes
        self.received = received
    }

    func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: self.bytes.count)
        buffer.writeBytes(self.bytes)
        context.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
        let channel = context.channel
        context.eventLoop.scheduleTask(in: .seconds(2)) { channel.close(promise: nil) }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = self.unwrapInboundIn(data)
        self.received.bytes += buffer.readBytes(length: buffer.readableBytes) ?? []
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.received.closed.succeed()
        context.fireChannelInactive()
    }
}


// Hand-built wire bytes for a server that says exactly what a test wants, driven through an EmbeddedChannel.
private enum Wire {
    static let clientSSL: UInt32 = 0x800

    static func littleEndian(_ value: Int, bytes: Int) -> [UInt8] {
        (0..<bytes).map { UInt8(truncatingIfNeeded: value >> (8 * $0)) }
    }

    /// Four bytes: the length (3, little endian) and the sequence id.
    static func header(length: Int, sequence: UInt8) -> [UInt8] {
        littleEndian(length, bytes: 3) + [sequence]
    }

    static func frame(_ payload: [UInt8], sequence: UInt8) -> [UInt8] {
        header(length: payload.count, sequence: sequence) + payload
    }

    /// A HandshakeV10 with the 4.1 protocol, secure connection, plugin auth and CLIENT_DEPRECATE_EOF.
    static func greeting(
        ssl: Bool = false,
        plugin: String = "caching_sha2_password",
        nonce: [UInt8] = Array(0x30..<0x44)
    ) -> [UInt8] {
        precondition(nonce.count == 20)
        // LONG_PASSWORD, CONNECT_WITH_DB, PROTOCOL_41, TRANSACTIONS, SECURE_CONNECTION, PLUGIN_AUTH,
        // PLUGIN_AUTH_LENENC_CLIENT_DATA, DEPRECATE_EOF (and SSL)
        var capabilities: UInt32 = 0x1 | 0x8 | 0x200 | 0x2000 | 0x8000 | 0x80000 | 0x200000 | 0x1000000
        if ssl { capabilities |= clientSSL }
        var p: [UInt8] = [10] + Array("8.0.36".utf8) + [0]
        p += [7, 0, 0, 0]                                                   // connection id
        p += Array(nonce[0..<8]) + [0]                                      // auth plugin data, part 1, and the filler
        p += littleEndian(Int(capabilities & 0xFFFF), bytes: 2)
        p += [255]                                                          // utf8mb4
        p += [2, 0]                                                         // status: autocommit
        p += littleEndian(Int(capabilities >> 16), bytes: 2)
        p += [21] + Array(repeating: 0, count: 10)                          // auth plugin data length, reserved
        p += Array(nonce[8..<20]) + [0]                                     // part 2 and its NUL
        p += Array(plugin.utf8) + [0]
        return p
    }

    /// The auth response inside a HandshakeResponse41 payload (user name, then a length-encoded response).
    static func authResponse(inHandshakeResponse payload: [UInt8]) -> [UInt8]? {
        guard payload.count > 33, let userEnd = payload[32...].firstIndex(of: 0), userEnd + 1 < payload.count else {
            return nil
        }
        let length = Int(payload[userEnd + 1])
        let start = userEnd + 2
        guard start + length <= payload.count else { return nil }
        return Array(payload[start..<(start + length)])
    }
}

/// A `MySQLConnectionHandler` behind the real decoder and encoder, with no socket. Whatever the client writes
/// comes back from `written()` as (sequence id, payload) pairs.
private struct Rig {
    let channel = EmbeddedChannel()
    let done: EventLoopPromise<Void>
    let outcome = OutcomeBox()

    final class OutcomeBox: @unchecked Sendable {
        var result: Result<Void, any Error>?
    }

    /// The error the handshake failed with, if it failed.
    var failure: (any Error)? {
        if case .failure(let error) = self.outcome.result { error } else { nil }
    }

    init(password: String? = "s3cret", tls: TLSConfiguration?, requireTLS: Bool) throws {
        let logger = Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }
        let sequence = MySQLPacketSequence()
        self.done = self.channel.eventLoop.makePromise(of: Void.self)
        let outcome = self.outcome
        self.done.futureResult.whenComplete { outcome.result = $0 }
        try self.channel.pipeline.syncOperations.addHandlers([
            ByteToMessageHandler(MySQLPacketDecoder(sequence: sequence, logger: logger)),
            MessageToByteHandler(MySQLPacketEncoder(sequence: sequence, logger: logger)),
            MySQLConnectionHandler(logger: logger, state: .handshake(.init(
                username: "tester",
                database: "test",
                password: password,
                tlsConfiguration: tls,
                serverHostname: nil,
                requireTLS: requireTLS,
                done: self.done
            )), sequence: sequence),
        ])
    }

    /// Bytes arriving from the server, in one read.
    func receive(_ bytes: [UInt8]) throws {
        var buffer = self.channel.allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        try self.channel.writeInbound(buffer)
    }

    /// Everything the client has written since the last call, split into wire packets.
    func written() throws -> [(sequence: UInt8, payload: [UInt8])] {
        var all = ByteBuffer()
        while var part = try self.channel.readOutbound(as: ByteBuffer.self) { all.writeBuffer(&part) }
        var packets: [(UInt8, [UInt8])] = []
        while let header = all.readInteger(endianness: .little, as: UInt32.self) {
            let length = Int(header & 0xFF_FFFF)
            packets.append((UInt8(header >> 24), all.readBytes(length: length) ?? []))
        }
        return packets
    }

    /// The first buffer the client wrote, as one wire packet.
    func firstWrittenPacket() throws -> (sequence: UInt8, payload: [UInt8])? {
        guard var buffer = try self.channel.readOutbound(as: ByteBuffer.self),
              let header = buffer.readInteger(endianness: .little, as: UInt32.self) else { return nil }
        return (UInt8(header >> 24), buffer.readBytes(length: Int(header & 0xFF_FFFF)) ?? [])
    }

    /// Settles the handshake promise so the test never leaks it, and closes the channel.
    func finish() {
        if self.outcome.result == nil { self.done.fail(MySQLError.closed) }
        _ = try? self.channel.finish()
    }
}
