import Logging
@testable import MySQLNIO
import NIOCore
import NIOEmbedded
import NIOSSL
import Testing

@Suite("caching_sha2_password with an empty password")
struct EmptyCachingSHA2PasswordTests {
    /// libmysqlclient sends an empty auth response when there is no password. A 32-byte scramble of the empty string
    /// makes the server ask for full authentication, which without TLS ends in "Access denied" (1045) for an account
    /// that has no password.
    @Test func emptyPasswordInTheHandshakeResponseIsAnEmptyAuthResponse() throws {
        let rig = try Rig(password: "")
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(), sequence: 0))
        let response = try #require(try rig.written().first)
        #expect(Wire.authResponse(inHandshakeResponse: response.payload) == [])
    }

    @Test func nilPasswordIsAnEmptyAuthResponseToo() throws {
        let rig = try Rig(password: nil)
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(), sequence: 0))
        let response = try #require(try rig.written().first)
        #expect(Wire.authResponse(inHandshakeResponse: response.payload) == [])
    }

    @Test func aPasswordStillGetsTheThirtyTwoByteScramble() throws {
        let rig = try Rig(password: "s3cret")
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(), sequence: 0))
        let response = try #require(try rig.written().first)
        #expect(Wire.authResponse(inHandshakeResponse: response.payload)?.count == 32)
    }

    /// The same after an auth switch request from the server (here from mysql_native_password).
    @Test func emptyPasswordAfterAnAuthSwitchIsAnEmptyResponse() throws {
        let rig = try Rig(password: "")
        defer { rig.finish() }
        try rig.receive(Wire.frame(Wire.greeting(plugin: "mysql_native_password"), sequence: 0))
        _ = try rig.written()
        let nonce = Array(0x30..<0x44) as [UInt8]
        try rig.receive(Wire.frame([0xFE] + Array("caching_sha2_password".utf8) + [0] + nonce + [0], sequence: 2))
        let response = try #require(try rig.written().first)
        #expect(response.payload == [])
    }
}


// Hand-built wire bytes for a server that says exactly what a test wants, driven through an EmbeddedChannel.
private enum Wire {
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
    /// `authDataLength` is the byte the server sends for the length of the auth plugin data.
    static func greeting(
        ssl: Bool = false,
        plugin: String = "caching_sha2_password",
        nonce: [UInt8] = Array(0x30..<0x44),
        authDataLength: UInt8 = 21
    ) -> [UInt8] {
        precondition(nonce.count == 20)
        // LONG_PASSWORD, CONNECT_WITH_DB, PROTOCOL_41, TRANSACTIONS, SECURE_CONNECTION, PLUGIN_AUTH,
        // PLUGIN_AUTH_LENENC_CLIENT_DATA, DEPRECATE_EOF (and SSL)
        var capabilities: UInt32 = 0x1 | 0x8 | 0x200 | 0x2000 | 0x8000 | 0x80000 | 0x200000 | 0x1000000
        if ssl { capabilities |= 0x800 }
        var p: [UInt8] = [10] + Array("8.0.36".utf8) + [0]
        p += [7, 0, 0, 0]                                                   // connection id
        p += Array(nonce[0..<8]) + [0]                                      // auth plugin data, part 1, and the filler
        p += littleEndian(Int(capabilities & 0xFFFF), bytes: 2)
        p += [255]                                                          // utf8mb4
        p += [2, 0]                                                         // status: autocommit
        p += littleEndian(Int(capabilities >> 16), bytes: 2)
        p += [authDataLength] + Array(repeating: 0, count: 10)              // auth plugin data length, reserved
        p += Array(nonce[8..<20]) + [0]                                     // part 2 and its NUL
        p += Array(plugin.utf8) + [0]
        return p
    }

    static let ok: [UInt8] = [0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00]

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
        var closed = false
    }

    init(password: String? = "s3cret", tls: TLSConfiguration? = nil) throws {
        let logger = Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }
        let sequence = MySQLPacketSequence()
        self.done = self.channel.eventLoop.makePromise(of: Void.self)
        let outcome = self.outcome
        self.done.futureResult.whenComplete { outcome.result = $0 }
        self.channel.closeFuture.whenComplete { _ in outcome.closed = true }
        try self.channel.pipeline.syncOperations.addHandlers([
            ByteToMessageHandler(MySQLPacketDecoder(sequence: sequence, logger: logger)),
            MessageToByteHandler(MySQLPacketEncoder(sequence: sequence, logger: logger)),
            MySQLConnectionHandler(logger: logger, state: .handshake(.init(
                username: "tester",
                database: "test",
                password: password,
                tlsConfiguration: tls,
                serverHostname: nil,
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

    /// Settles the handshake promise so the test never leaks it, and closes the channel.
    func finish() {
        if self.outcome.result == nil { self.done.fail(MySQLError.closed) }
        _ = try? self.channel.finish()
    }
}
