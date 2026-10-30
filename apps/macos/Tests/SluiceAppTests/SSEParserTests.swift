import XCTest
@testable import SluiceApp

final class SSEParserTests: XCTestCase {
    private func parse(_ text: String) throws -> [SSEFrame] {
        var parser = SSEParser()
        return try text.utf8.compactMap { try parser.append($0) }
    }

    func testCoreFramesAndKeepalives() throws {
        let frames = try parse(": sluice events\n\nevent: traffic\ndata: {\"up\":1}\n\n: keepalive\n\nevent: conn_open\ndata: {\"id\":71}\n\nevent: conn_close\ndata: {\"id\":71}\n\n")
        XCTAssertEqual(frames, [SSEFrame(event: "traffic", data: #"{"up":1}"#),
                                SSEFrame(event: "conn_open", data: #"{"id":71}"#),
                                SSEFrame(event: "conn_close", data: #"{"id":71}"#)])
    }

    func testMultilineDataUnicodeBOMAndMixedLineEndings() throws {
        // Feeding one byte at a time splits both CRLF pairs and UTF-8 characters.
        let frames = try parse("\u{FEFF}event: log\r\ndata: 节点\r\ndata:  第二行\r\n\r\ndata: last\r\r")
        XCTAssertEqual(frames, [SSEFrame(event: "log", data: "节点\n 第二行"), SSEFrame(event: "message", data: "last")])
    }

    func testEmptyDataUnknownFieldsAndEventReset() throws {
        let frames = try parse("event: ignored\n\nid: 9\nretry: 1000\ndata\n\nevent: first\nevent: last\ndata:value:more\n\ndata:\n\n")
        XCTAssertEqual(frames, [SSEFrame(event: "message", data: ""),
                                SSEFrame(event: "last", data: "value:more"),
                                SSEFrame(event: "message", data: "")])
    }

    func testIncompleteFramesAreNotDispatchedAndReconnectStartsFresh() throws {
        XCTAssertEqual(try parse("event: log\ndata: incomplete"), [])
        XCTAssertEqual(try parse("event: log\ndata: incomplete\n"), [])
        XCTAssertEqual(try parse("data: fresh\n\n"), [SSEFrame(event: "message", data: "fresh")])
    }

    func testOversizedFramesFailInsteadOfGrowingWithoutBound() {
        XCTAssertThrowsError(try parse("data: " + String(repeating: "a", count: 1_048_577)))
        XCTAssertThrowsError(try parse(String(repeating: "data: 123456789\n", count: 110_000)))
    }
}
