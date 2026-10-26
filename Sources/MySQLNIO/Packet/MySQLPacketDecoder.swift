import NIOCore
import Logging

public struct MySQLPacketDecoder: ByteToMessageDecoder {
    public typealias InboundOut = MySQLPacket

    /// The largest logical packet the decoder joins by default: 256 MiB, four times the `max_allowed_packet` that
    /// MySQL 8.0 and later ship with (64 MiB; MySQL's own maximum is 1 GiB).
    public static let defaultMaximumPacketSize = 256 * 1024 * 1024

    public let sequence: MySQLPacketSequence
    let logger: Logger
    /// A logical packet (one result row, for example) may span several wire packets of 0xFFFFFF bytes. The decoder
    /// refuses one whose parts add up to more than this as soon as a part's header says so, before the part's data
    /// arrives, so a huge row cannot grow the buffer without bound.
    public let maximumPacketSize: Int

    public init(sequence: MySQLPacketSequence, logger: Logger) {
        self.init(sequence: sequence, logger: logger, maximumPacketSize: Self.defaultMaximumPacketSize)
    }

    public init(sequence: MySQLPacketSequence, logger: Logger, maximumPacketSize: Int) {
        self.sequence = sequence
        self.logger = logger
        self.maximumPacketSize = maximumPacketSize
    }
    
    public mutating func decode(context: ChannelHandlerContext, buffer: inout ByteBuffer) throws -> DecodingState {
        // header = 01     00 00 01
        //          <seq>  <length>
        // A wire packet of exactly 0xFFFFFF bytes is continued by the next one (MySQL's "sending more than 16 MB").
        // Scan the headers first without copying, and join the parts once, when the whole logical packet is here.
        var offset = buffer.readerIndex
        var total = 0
        var parts = 0
        var sequenceID: UInt32 = 0
        while true {
            guard let header = buffer.getInteger(at: offset, endianness: .little, as: UInt32.self) else {
                return .needMoreData
            }
            let length = Int(header & 0x00_FF_FF_FF)
            sequenceID = header >> 24
            guard total + length <= self.maximumPacketSize else {
                throw MySQLError.packetTooLarge(limit: self.maximumPacketSize)
            }
            guard buffer.writerIndex - (offset + 4) >= length else {
                return .needMoreData
            }
            total += length
            parts += 1
            offset += 4 + length
            if length < 0x00_FF_FF_FF { break }
        }
        let payload: ByteBuffer
        if parts == 1 {
            buffer.moveReaderIndex(forwardBy: 4)
            payload = buffer.readSlice(length: total)!
        } else {
            var whole = context.channel.allocator.buffer(capacity: total)
            for _ in 0..<parts {
                let header = buffer.readInteger(endianness: .little, as: UInt32.self)!
                var part = buffer.readSlice(length: Int(header & 0x00_FF_FF_FF))!
                whole.writeBuffer(&part)
            }
            payload = whole
        }
        let packet = MySQLPacket(payload: payload)
        self.logger.trace("MySQLPacketDecoder.decode: \(packet)")
        self.sequence.current = UInt8(sequenceID & 0xFF)
        context.fireChannelRead(self.wrapInboundOut(packet))
        return .continue
    }
    
    public mutating func decodeLast(context: ChannelHandlerContext, buffer: inout ByteBuffer, seenEOF: Bool) throws -> DecodingState {
        .needMoreData
    }
}
