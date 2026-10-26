import Logging
@testable import MySQLNIO
import NIOCore
import NIOEmbedded
import NIOSSL
import Testing

@Suite("Two-byte collation ids in column definitions")
struct CollationIDTests {
    static func lengthEncoded(_ text: String) -> [UInt8] { [UInt8(text.utf8.count)] + Array(text.utf8) }

    /// A ColumnDefinition41 whose `character_set` field is the two-byte collation id `collation`.
    static func definition(collation: UInt16) -> MySQLPacket {
        var bytes = lengthEncoded("def") + lengthEncoded("shop") + lengthEncoded("t") + lengthEncoded("t")
        bytes += lengthEncoded("name") + lengthEncoded("name")
        bytes += [0x0C, UInt8(collation & 0xFF), UInt8(collation >> 8)]
        bytes += [255, 0, 0, 0]                          // column length
        bytes += [0xFD]                                  // VAR_STRING
        bytes += [0, 0, 0, 0, 0]                         // flags, decimals, filler
        return MySQLPacket(payload: ByteBuffer(bytes: bytes))
    }

    /// The character set field is two bytes, the collation id the values are sent in. The server sends the session's
    /// collation for text columns, which can be above 255: MySQL's utf8mb4_0900_as_cs is 278, MariaDB's uca1400
    /// collations are above 2,000. Upstream read one byte and required the next to be 0, so such a result failed with
    /// a protocol error.
    @Test(arguments: [UInt16(63), 255, 256, 278, 303, 2304, 0xFFFF])
    func collationIdsAboveTwoFiftyFiveDecode(collation: UInt16) throws {
        var packet = Self.definition(collation: collation)
        let column = try MySQLProtocol.ColumnDefinition41.decode(from: &packet, capabilities: .clientDefault)
        #expect(column.collationID == collation)
        #expect(column.characterSet.rawValue == UInt8(truncatingIfNeeded: collation))
        #expect(column.name == "name")
        #expect(column.columnLength == 255)
        #expect(column.columnType == .varString)
    }
}
