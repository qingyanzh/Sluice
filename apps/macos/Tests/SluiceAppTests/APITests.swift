import Foundation
import XCTest
@testable import SluiceApp

final class APITests: XCTestCase {
    private func session() -> URLSession {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ControlAPIStub.self]
        return URLSession(configuration: configuration)
    }

    func testConnectionsOnlyFallBackFor404() async throws {
        let session = session()
        defer { session.invalidateAndCancel() }
        let connections = try await APIClient(port: 200, session: session).connections()
        XCTAssertNotNil(connections)
        XCTAssertTrue(connections?.isEmpty == true)
        let missing = try await APIClient(port: 404, session: session).connections()
        XCTAssertNil(missing)

        for status in [405, 500] {
            do {
                _ = try await APIClient(port: status, session: session).connections()
                XCTFail("HTTP \(status) must not enable log fallback")
            } catch let error as APIError {
                XCTAssertEqual(error.status, status)
            }
        }
    }

    func testMalformedConnectionsRemainAnError() async throws {
        let session = session()
        defer { session.invalidateAndCancel() }
        do {
            _ = try await APIClient(port: 201, session: session).connections()
            XCTFail("An invalid successful response must not enable log fallback")
        } catch is DecodingError {
            // The caller retains the last good API snapshot.
        }
    }

    func testDNSReadAndFlushUseTheirRealEndpoints() async throws {
        let session = session()
        defer { session.invalidateAndCancel() }
        let api = APIClient(port: 200, session: session)
        let cache = try await api.dns()
        XCTAssertEqual(cache.entries.first?.name, "example.com")
        let result = try await api.flushDNS()
        XCTAssertEqual(result.flushed, 1)
    }

    func testStatsUseRealEndpointAndOnlyFallBackFor404() async throws {
        let session = session()
        defer { session.invalidateAndCancel() }
        let stats = try await APIClient(port: 200, session: session).stats()
        XCTAssertEqual(stats?.up, 123)
        XCTAssertEqual(stats?.down, 456)
        let missing = try await APIClient(port: 404, session: session).stats()
        XCTAssertNil(missing)
        for status in [405, 500] {
            do {
                _ = try await APIClient(port: status, session: session).stats()
                XCTFail("HTTP \(status) must not enable overall-only fallback")
            } catch let error as APIError {
                XCTAssertEqual(error.status, status)
            }
        }
        do {
            _ = try await APIClient(port: 201, session: session).stats()
            XCTFail("Malformed stats must not enable fallback")
        } catch is DecodingError {}
    }

    func testDiagnosticsExportUsesGETAndEscapesOutputPath() async throws {
        let session = session()
        defer { session.invalidateAndCancel() }
        let output = URL(fileURLWithPath: "/tmp/Sluice 诊断 &?#.zip")
        let file = try await APIClient(port: 200, session: session).exportDiagnostics(to: output)
        XCTAssertEqual(file.path, output.path)
        do {
            _ = try await APIClient(port: 500, session: session).exportDiagnostics(to: output)
            XCTFail("Server failures must reach the export UI")
        } catch let error as APIError {
            XCTAssertEqual(error.status, 500)
            XCTAssertEqual(error.message, "export failed")
        }
        do {
            _ = try await APIClient(port: 201, session: session).exportDiagnostics(to: output)
            XCTFail("A relative path cannot be revealed in Finder")
        } catch let error as APIError {
            XCTAssertTrue(error.message.contains("无效"))
        }
    }
}

/// Port selects the HTTP status; all requests are intercepted without opening sockets.
private final class ControlAPIStub: URLProtocol {
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let url = request.url else { return }
        let status = url.port ?? 500
        let body: String
        switch (request.httpMethod, url.path) {
        case ("GET", "/v1/connections"):
            body = status == 200 ? "[]" : "{}"
        case ("GET", "/v1/dns"):
            body = #"{"entries":[{"name":"example.com","type":"A","ttl":30,"answers":["192.0.2.1"]}]}"#
        case ("POST", "/v1/dns/flush"):
            body = #"{"flushed":1}"#
        case ("GET", "/v1/stats"):
            body = status == 200
                ? #"{"up":123,"down":456,"active":2,"policies":[],"nodes":[],"history":[]}"#
                : "{}"
        case ("GET", "/v1/diag"):
            let path = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?.first { $0.name == "path" }?.value
            XCTAssertEqual(path, "/tmp/Sluice 诊断 &?#.zip")
            XCTAssertEqual(request.timeoutInterval, 180)
            body = status == 200 ? #"{"path":"/tmp/Sluice 诊断 &?#.zip"}"#
                : status == 201 ? #"{"path":"relative.zip"}"# : #"{"error":"export failed"}"#
        default:
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }
        let response = HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1",
                                       headerFields: ["Content-Type": "application/json"])!
        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
