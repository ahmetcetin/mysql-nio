import Logging
@testable import MySQLNIO
import NIOCore
import NIOEmbedded
import Testing

@Suite("Packets of 16 MiB and more")
struct MultiPacketPayloadTests {
    static let max = 0xFF_FFFF

    static func channel(cap: Int = MySQLPacketDecoder.defaultMaximumPacketSize) throws -> (EmbeddedChannel, MySQLPacketSequence) {
        let sequence = MySQLPacketSequence()
        let logger = Logger(label: "test") { _ in SwiftLogNoOpLogHandler() }
        let channel = EmbeddedChannel()
        try channel.pipeline.syncOperations.addHandler(
            ByteToMessageHandler(MySQLPacketDecoder(sequence: sequence, logger: logger, maximumPacketSize: cap))
        )
        return (channel, sequence)
    }

    /// A wire packet: 3 bytes of length (little endian), the sequence id, then `length` bytes of `fill`.
    static func wire(length: Int, sequence: UInt8, fill: UInt8) -> ByteBuffer {
        var buffer = ByteBuffer()
        buffer.writeBytes([UInt8(length & 0xFF), UInt8(length >> 8 & 0xFF), UInt8(length >> 16 & 0xFF), sequence])
        buffer.writeRepeatingByte(fill, count: length)
        return buffer
    }

    @Test func singlePacketIsUnchanged() throws {
        let (channel, sequence) = try Self.channel()
        try channel.writeInbound(Self.wire(length: 100, sequence: 5, fill: 7))
        let packet = try #require(try channel.readInbound(as: MySQLPacket.self))
        #expect(packet.payload.readableBytes == 100)
        #expect(sequence.current == 5)
        #expect(try channel.readInbound(as: MySQLPacket.self) == nil)
    }

    /// A wire packet of exactly 0xFFFFFF bytes means "more follows"; the logical packet ends with a shorter one,
    /// which is empty when the payload is an exact multiple. Upstream treated each wire packet as a whole message.
    @Test func maxLengthThenEmptyJoinsToOnePayload() throws {
        let (channel, sequence) = try Self.channel()
        var bytes = Self.wire(length: Self.max, sequence: 1, fill: 1)
        var tail = Self.wire(length: 0, sequence: 2, fill: 0)
        bytes.writeBuffer(&tail)
        try channel.writeInbound(bytes)
        let packet = try #require(try channel.readInbound(as: MySQLPacket.self))
        #expect(packet.payload.readableBytes == Self.max)
        #expect(sequence.current == 2)
        #expect(try channel.readInbound(as: MySQLPacket.self) == nil)
    }

    /// Three parts delivered in pieces that cut inside a header, inside a part and between parts: no packet until the
    /// last byte is there, then one with the parts in order, and the small packet behind it comes out second.
    @Test func partsDeliveredInPiecesJoinOnceTheLastByteArrives() throws {
        let (channel, sequence) = try Self.channel()
        var all = Self.wire(length: Self.max, sequence: 1, fill: 1)
        var second = Self.wire(length: Self.max, sequence: 2, fill: 2)
        var third = Self.wire(length: 5, sequence: 3, fill: 3)
        var next = Self.wire(length: 3, sequence: 4, fill: 9)
        all.writeBuffer(&second)
        all.writeBuffer(&third)
        all.writeBuffer(&next)
        let total = 2 * Self.max + 5
        let cuts = [2, 1000, Self.max + 4, Self.max + 6, 2 * Self.max + 8 + 4 + 2, 2 * Self.max + 12 + 4]
        var start = 0
        for cut in cuts {
            try channel.writeInbound(all.getSlice(at: start, length: cut - start)!)
            #expect(try channel.readInbound(as: MySQLPacket.self) == nil, "a packet before byte \(cut)")
            start = cut
        }
        try channel.writeInbound(all.getSlice(at: start, length: all.readableBytes - start)!)
        let packet = try #require(try channel.readInbound(as: MySQLPacket.self))
        #expect(packet.payload.readableBytes == total)
        #expect(packet.payload.getInteger(at: 0, as: UInt8.self) == 1)
        #expect(packet.payload.getInteger(at: Self.max, as: UInt8.self) == 2)
        #expect(packet.payload.getInteger(at: total - 1, as: UInt8.self) == 3)
        let small = try #require(try channel.readInbound(as: MySQLPacket.self))
        #expect(Array(small.payload.readableBytesView) == [9, 9, 9])
        #expect(sequence.current == 4)
    }

    /// The decoder refuses a logical packet whose parts add up to more than `maximumPacketSize` as soon as the header
    /// of the part that crosses the limit has arrived, before that part's data, so a huge row cannot grow the buffer
    /// without bound.
    @Test func overTheLimitFailsOnTheHeaderBeforeItsData() throws {
        let limit = Self.max + 1000
        let (channel, _) = try Self.channel(cap: limit)
        var bytes = Self.wire(length: Self.max, sequence: 1, fill: 1)
        bytes.writeBytes([UInt8(2000 & 0xFF), UInt8(2000 >> 8), 0, 2])      // only the second part's header
        do {
            try channel.writeInbound(bytes)
            Issue.record("expected packetTooLarge")
        } catch MySQLError.packetTooLarge(let reported) {
            #expect(reported == limit)
        }
        _ = try? channel.finish()
    }

    @Test func atTheLimitIsStillJoined() throws {
        let (channel, _) = try Self.channel(cap: Self.max + 5)
        var bytes = Self.wire(length: Self.max, sequence: 1, fill: 1)
        var tail = Self.wire(length: 5, sequence: 2, fill: 2)
        bytes.writeBuffer(&tail)
        try channel.writeInbound(bytes)
        #expect(try channel.readInbound(as: MySQLPacket.self)?.payload.readableBytes == Self.max + 5)
    }

    @Test func theDefaultLimitIs256MiB() {
        #expect(MySQLPacketDecoder.defaultMaximumPacketSize == 256 * 1024 * 1024)
    }

    /// `[0xFE, 0, 0, 2, 0]` is an EOF packet. A row whose first value is 2^24 bytes or longer starts with 0xFE too (the
    /// 8-byte length marker) but is at least 0xFFFFFF bytes long, so it is not.
    @Test func isEOFIgnoresLongRowsThatStartWithFE() {
        #expect(MySQLPacket(payload: ByteBuffer(bytes: [0xFE, 0, 0, 2, 0])).isEOF)
        var row = ByteBuffer(bytes: [0xFE, 0, 0, 0, 1, 0, 0, 0, 0])             // 2^24 as an 8-byte length
        row.writeRepeatingByte(0x78, count: 0x100_0000)
        #expect(!MySQLPacket(payload: row).isEOF)
    }
}
