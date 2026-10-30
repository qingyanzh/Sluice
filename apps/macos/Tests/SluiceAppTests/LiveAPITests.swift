import AppKit
import Foundation
import XCTest
@testable import SluiceApp

private final class MenuTrackingView: RowContextMenu.MenuView {
    var onTrack: ((NSMenu, NSEvent) -> Void)?

    override func track(_ menu: NSMenu, with event: NSEvent) { onTrack?(menu, event) }
}

final class LiveAPITests: XCTestCase {
    private let active = #"{"id":71,"start_ms":1793286962123,"network":"tcp","target":"example.com:443","src":"127.0.0.1:53721","rule":"FINAL","policy":"Proxy","chain":["Proxy","Auto","HK"],"outbound":"HK","process":"Safari","up":4294967296,"down":9000,"rate_up":1024,"rate_down":2048}"#

    @MainActor
    func testOpenConnectionMenuRetainsItsTargetAcrossRowRefreshes() throws {
        let original = try JSONDecoder().decode(ActiveConnection.self, from: Data(active.utf8))
        let replacement = try JSONDecoder().decode(ActiveConnection.self, from: Data(active.replacingOccurrences(of: #""id":71"#, with: #""id":72"#).utf8))
        var closed: [UInt64] = []
        var copied: [String] = []
        var view: RowContextMenu.MenuView? = RowContextMenu.MenuView()
        view?.makeMenu = {
            ActiveConnectionMenu.menu(connection: original, canClose: true, copy: { copied.append($0) }) { closed.append($0) }
        }
        let event = try XCTUnwrap(NSEvent.mouseEvent(with: .rightMouseDown, location: .zero, modifierFlags: [],
                                                  timestamp: 0, windowNumber: 0, context: nil, eventNumber: 0,
                                                  clickCount: 1, pressure: 0))
        let menu = try XCTUnwrap(view?.menu(for: event))
        // A poll can replace/reorder rows while this menu is still tracking.
        view?.makeMenu = { ActiveConnectionMenu.menu(connection: replacement, canClose: true) { closed.append($0) } }
        XCTAssertEqual(menu.items.map(\.title), ["复制目标", "复制策略链", "", "断开连接"])
        XCTAssertTrue(menu.items[3].isEnabled)
        let refreshedMenu = try XCTUnwrap(view?.menu(for: event))
        view = nil
        // Dispatch through AppKit without requiring access to the system pasteboard.
        for index in [0, 1] {
            let item = menu.items[index]
            let target = try XCTUnwrap(item.target)
            XCTAssertFalse(target === item)
            XCTAssertTrue(NSApplication.shared.sendAction(try XCTUnwrap(item.action), to: target, from: item))
        }
        XCTAssertEqual(copied, [original.target, original.policyChain])
        menu.performActionForItem(at: 3)
        refreshedMenu.performActionForItem(at: 3)
        XCTAssertEqual(closed, [71, 72])
    }

    @MainActor
    func testRowMenuMouseEventsTrackSnapshotAcrossRefresh() throws {
        let view = MenuTrackingView()
        var performed: [String] = []
        var trackedEvents: [NSEvent.EventType] = []
        view.makeMenu = {
            let menu = RowContextMenu.Menu()
            menu.addAction("Original") { performed.append("original") }
            return menu
        }
        view.onTrack = { menu, event in
            trackedEvents.append(event.type)
            // Simulate a SwiftUI update while AppKit is tracking the open menu.
            view.makeMenu = {
                let menu = RowContextMenu.Menu()
                menu.addAction("Replacement") { performed.append("replacement") }
                return menu
            }
            menu.performActionForItem(at: 0)
        }
        defer { view.onTrack = nil }
        let rightClick = try XCTUnwrap(NSEvent.mouseEvent(with: .rightMouseDown, location: .zero, modifierFlags: [],
                                                        timestamp: 0, windowNumber: 0, context: nil, eventNumber: 0,
                                                        clickCount: 1, pressure: 0))
        let controlClick = try XCTUnwrap(NSEvent.mouseEvent(with: .leftMouseDown, location: .zero, modifierFlags: [.control],
                                                          timestamp: 0, windowNumber: 0, context: nil, eventNumber: 1,
                                                          clickCount: 1, pressure: 0))
        view.rightMouseDown(with: rightClick)
        view.mouseDown(with: controlClick)
        XCTAssertEqual(trackedEvents, [.rightMouseDown, .leftMouseDown])
        XCTAssertEqual(performed, ["original", "replacement"])
    }

    @MainActor
    func testExpiredOrStoppedConnectionMenuDisablesDisconnect() throws {
        let connection = try JSONDecoder().decode(ActiveConnection.self, from: Data(active.utf8))
        let menu = ActiveConnectionMenu.menu(connection: connection, canClose: false) { _ in XCTFail("Cannot close a stale row") }
        XCTAssertFalse(menu.autoenablesItems)
        XCTAssertFalse(menu.items[3].isEnabled)
        XCTAssertTrue(menu.items[0].isEnabled)
        XCTAssertTrue(menu.items[1].isEnabled)
    }

    func testActiveConnectionDecodesCountersChainAndNullableMetadata() throws {
        let records = try JSONDecoder().decode([ActiveConnection].self, from: Data("[\(active)]".utf8))
        let connection = try XCTUnwrap(records.first)
        XCTAssertEqual(connection.id, 71)
        XCTAssertEqual(connection.startMs, 1793286962123)
        XCTAssertEqual(connection.network, "tcp")
        XCTAssertEqual(connection.policyChain, "Proxy → Auto → HK")
        XCTAssertEqual(connection.up, 4_294_967_296)
        XCTAssertEqual(connection.down, 9000)
        XCTAssertEqual(connection.rateUp, 1024)
        XCTAssertEqual(connection.rateDown, 2048)
        for query in ["aUtO", "safari", "example.com", "127.0.0.1"] { XCTAssertTrue(connection.matches(query)) }
        XCTAssertFalse(connection.matches("other-node"))
        let nullable = active.replacingOccurrences(of: #""src":"127.0.0.1:53721""#, with: #""src":null"#)
            .replacingOccurrences(of: #""process":"Safari""#, with: #""process":null"#)
        let noMetadata = try JSONDecoder().decode(ActiveConnection.self, from: Data(nullable.utf8))
        XCTAssertNil(noMetadata.src)
        XCTAssertNil(noMetadata.process)
        XCTAssertThrowsError(try JSONDecoder().decode(Connection.self, from: Data(active.utf8)),
                             "Active IDs must never be confused with routing-history IDs")
    }

    func testActiveSnapshotKeepsOpensAndClosesReceivedDuringRefresh() throws {
        let closed = try JSONDecoder().decode(ActiveConnection.self, from: Data(active.utf8))
        let opened = try JSONDecoder().decode(ActiveConnection.self,
            from: Data(active.replacingOccurrences(of: "\"id\":71", with: "\"id\":72").utf8))
        let unchanged = try JSONDecoder().decode(ActiveConnection.self,
            from: Data(active.replacingOccurrences(of: "\"id\":71", with: "\"id\":73").utf8))
        let rows = ActiveConnection.reconcile([unchanged, closed], current: [opened, unchanged], changedIDs: [71, 72])
        XCTAssertEqual(rows.map(\.id), [72, 73], "A stale snapshot must neither resurrect a closed row nor lose a new row")
    }

    func testActiveOrderDoesNotChangeWithResponseOrderOrRates() throws {
        let first = try JSONDecoder().decode(ActiveConnection.self, from: Data(active.utf8))
        let second = try JSONDecoder().decode(ActiveConnection.self,
            from: Data(active.replacingOccurrences(of: "\"id\":71", with: "\"id\":72")
                .replacingOccurrences(of: "\"rate_up\":1024", with: "\"rate_up\":999999").utf8))
        for snapshot in [[first, second], [second, first]] {
            XCTAssertEqual(ActiveConnection.reconcile(snapshot, current: [], changedIDs: []).map(\.id), [71, 72])
        }
    }

    func testNodeTestDecodesSuccessAndFailure() throws {
        let success = #"{"node":"HK","outbound":"HK","ok":true,"connect_ms":42,"latency_ms":85,"status":204,"error":null}"#
        let result = try JSONDecoder().decode(NodeTestResult.self, from: Data(success.utf8))
        XCTAssertEqual(result.node, "HK")
        XCTAssertEqual(result.outbound, "HK")
        XCTAssertTrue(result.ok)
        XCTAssertEqual(result.connectMs, 42)
        XCTAssertEqual(result.latencyMs, 85)
        XCTAssertEqual(result.status, 204)
        XCTAssertNil(result.error)

        let failure = #"{"node":"HK","outbound":null,"ok":false,"connect_ms":null,"latency_ms":null,"status":null,"error":"connect timed out"}"#
        let failed = try JSONDecoder().decode(NodeTestResult.self, from: Data(failure.utf8))
        XCTAssertFalse(failed.ok)
        XCTAssertNil(failed.outbound)
        XCTAssertNil(failed.connectMs)
        XCTAssertNil(failed.latencyMs)
        XCTAssertNil(failed.status)
        XCTAssertEqual(failed.error, "connect timed out")
    }

    func testGroupTestDecodesPerOptionResultsIncludingFailure() throws {
        let data = Data(#"{"tested":"Auto","selected":"HK","results":[{"name":"HK","latency_ms":85},{"name":"US","latency_ms":null}]}"#.utf8)
        let result = try JSONDecoder().decode(GroupTestResult.self, from: data)
        XCTAssertEqual(result.tested, "Auto")
        XCTAssertEqual(result.selected, "HK")
        XCTAssertEqual(result.results.map(\.name), ["HK", "US"])
        XCTAssertEqual(result.results[0].latencyMs, 85)
        XCTAssertNil(result.results[1].latencyMs)
    }

    @MainActor
    func testURLSessionByteStreamDispatchesFramesAndSurfacesEOF() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [LiveAPIStub.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        var opened = false
        var frames: [SSEFrame] = []
        do {
            try await APIClient(port: 200, session: session).events {
                opened = true
            } receive: { frames.append($0) }
            XCTFail("EOF must trigger the reconnect path")
        } catch let error as APIError {
            XCTAssertEqual(error.message, "事件流已结束")
        }
        XCTAssertTrue(opened)
        XCTAssertEqual(frames, [SSEFrame(event: "log", data: #"{"message":"节点"}"#)])
    }

    func testLiveEndpointsAndEncodedNames() async throws {
        let config = URLSessionConfiguration.ephemeral
        config.protocolClasses = [LiveAPIStub.self]
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }
        let api = APIClient(port: 200, session: session)
        let active = try await api.activeConnections()
        XCTAssertTrue(active.isEmpty)
        let result = try await api.test(node: "HK 东京/#%+?")
        XCTAssertEqual(result.connectMs, 10)
        let group = try await api.test(group: "Auto")
        XCTAssertEqual(group.results.first?.latencyMs, 20)
        try await api.closeConnection(71)
        try await api.closeAllConnections()
        try await api.switchProfile(path: "/tmp/工作 #+%.conf")
        do {
            try await APIClient(port: 400, session: session).switchProfile(path: "/tmp/工作 #+%.conf")
            XCTFail("Validation failure must be surfaced")
        } catch let error as APIError {
            XCTAssertEqual(error.status, 400)
            XCTAssertEqual(error.localizedDescription, "line 9: invalid policy")
        }
    }
}

private final class LiveAPIStub: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else { return }
        if url.path == "/v1/events" {
            let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: "HTTP/1.1",
                                           headerFields: ["Content-Type": "text/event-stream"])!
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            for byte in ": keepalive\n\nevent: log\r\ndata: {\"message\":\"节点\"}\r\n\r\n".utf8 {
                client?.urlProtocol(self, didLoad: Data([byte]))
            }
            client?.urlProtocolDidFinishLoading(self)
            return
        }
        let body: String
        switch (request.httpMethod, url.path) {
        case ("GET", "/v1/connections/active"): body = "[]"
        case ("DELETE", "/v1/connections/71"): body = #"{"closed":1,"id":71}"#
        case ("DELETE", "/v1/connections"): body = #"{"closed":3}"#
        case ("POST", "/v1/policies/Auto/test"):
            body = #"{"tested":"Auto","selected":"HK","results":[{"name":"HK","latency_ms":20}]}"#
        case ("POST", "/v1/profile"):
            guard URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first(where: { $0.name == "path" })?.value == "/tmp/工作 #+%.conf" else {
                client?.urlProtocol(self, didFailWithError: URLError(.badURL)); return
            }
            body = url.port == 400 ? #"{"error":"line 9: invalid policy"}"# : #"{"reloaded":true}"#
        default:
            let encoded = URLComponents(url: url, resolvingAgainstBaseURL: false)?.percentEncodedPath ?? ""
            guard request.httpMethod == "POST", encoded == "/v1/nodes/HK%20%E4%B8%9C%E4%BA%AC%2F%23%25%2B%3F/test" else {
                client?.urlProtocol(self, didFailWithError: URLError(.badURL)); return
            }
            body = #"{"node":"HK","outbound":"HK","ok":true,"connect_ms":10,"latency_ms":20,"status":204,"error":null}"#
        }
        let response = HTTPURLResponse(url: url, statusCode: url.port == 400 ? 400 : 200, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}
