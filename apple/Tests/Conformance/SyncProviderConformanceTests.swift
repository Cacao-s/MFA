import XCTest

/// Drives every case in `conformance/vectors/sync-provider.json` against the
/// real `HTTPProvider`.
///
/// The same decision table is written once per platform. What keeps the three
/// honest is not that they were written together — they were — but that each
/// is checked against the same file. This is the Apple copy's check; the
/// Windows copy has `conformance/dotnet` and the Android copy has a
/// Robolectric test, both reading this same JSON.
///
/// This target compiles only `Sources/Sync/SyncProvider.swift` and
/// `Sources/Sync/HTTPProvider.swift`, which import nothing but Foundation. So
/// it needs neither the Rust XCFramework nor a device, and runs on a bare
/// checkout with Xcode on it.
final class SyncProviderConformanceTests: XCTestCase {

    func testEveryCaseMatchesTheSharedVectors() async throws {
        let vectors = try loadVectors()
        let token = try XCTUnwrap(vectors["token"] as? String)
        let cases = try XCTUnwrap(vectors["cases"] as? [[String: Any]])
        XCTAssertFalse(cases.isEmpty, "the vectors are empty")

        for vector in cases {
            try await run(vector, token: token)
        }
    }

    /// An addition to the table must not pass by being ignored here.
    func testEveryCaseDescribesSomethingThisSuiteUnderstands() throws {
        let vectors = try loadVectors()
        let cases = try XCTUnwrap(vectors["cases"] as? [[String: Any]])

        for vector in cases {
            _ = try flavour(try XCTUnwrap(vector["flavour"] as? String))

            let operation = try XCTUnwrap(vector["operation"] as? String)
            XCTAssertTrue(["fetch", "put"].contains(operation), operation)

            let expect = try XCTUnwrap(vector["expect"] as? [String: Any])
            let outcome = try XCTUnwrap(expect["outcome"] as? String)
            let allowed = operation == "fetch"
                ? ["fetched", "absent", "error"]
                : ["written", "lost_race", "error"]
            XCTAssertTrue(allowed.contains(outcome), "\(operation)/\(outcome)")
        }
    }

    // MARK: - one case

    private func run(_ vector: [String: Any], token: String) async throws {
        let id = try XCTUnwrap(vector["id"] as? String)
        let exchanges = try XCTUnwrap(vector["exchanges"] as? [[String: Any]])
        let operation = try XCTUnwrap(vector["operation"] as? String)
        let expect = try XCTUnwrap(vector["expect"] as? [String: Any])
        let outcome = try XCTUnwrap(expect["outcome"] as? String)
        let name = try XCTUnwrap(vector["name"] as? String)

        ScriptedProtocol.script(exchanges)
        defer { ScriptedProtocol.reset() }

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [ScriptedProtocol.self]
        let provider = HTTPProvider(
            flavour: try flavour(try XCTUnwrap(vector["flavour"] as? String)),
            location: try XCTUnwrap(vector["location"] as? String),
            token: token,
            session: URLSession(configuration: configuration)
        )

        switch (outcome, operation) {
        case ("error", _):
            do {
                if operation == "fetch" {
                    _ = try await provider.fetch(name)
                } else {
                    _ = try await provider.put(
                        name,
                        bytes: try body(vector),
                        ifRevision: expectedRevision(vector)
                    )
                }
                XCTFail("\(id): expected a failure")
            } catch {
                // Not the outcome under test, but worth asserting wherever a
                // message is built from a response: the token travels in a
                // header, and an error body can echo the request back.
                let message = (error as? LocalizedError)?.errorDescription
                    ?? String(describing: error)
                XCTAssertFalse(
                    message.contains(token),
                    "\(id): the failure message carries the token"
                )
            }

        case ("absent", _):
            let fetched = try await provider.fetch(name)
            XCTAssertNil(fetched, id)

        case ("fetched", _):
            let fetched = try await provider.fetch(name)
            let unwrapped = try XCTUnwrap(fetched, id)
            XCTAssertEqual(unwrapped.revision, expect["revision"] as? String, id)
            XCTAssertEqual(unwrapped.bytes, try data(expect["body_base64"] as? String), id)

        case ("lost_race", _):
            let revision = try await provider.put(
                name,
                bytes: try body(vector),
                ifRevision: expectedRevision(vector)
            )
            XCTAssertNil(revision, id)

        case ("written", _):
            let revision = try await provider.put(
                name,
                bytes: try body(vector),
                ifRevision: expectedRevision(vector)
            )
            XCTAssertEqual(revision, expect["revision"] as? String, id)

        default:
            XCTFail("\(id): unhandled outcome \(outcome)")
        }

        try assertRequests(id: id, exchanges: exchanges)
    }

    /// Checks that the implementation sent what the case says it should.
    ///
    /// Half the table is about the request rather than the response: whether a
    /// write carried its guard, and which verb GitLab was given. A client that
    /// reads responses correctly and builds requests wrongly fails in
    /// production and nowhere else.
    private func assertRequests(id: String, exchanges: [[String: Any]]) throws {
        let sent = ScriptedProtocol.seen
        XCTAssertEqual(sent.count, exchanges.count - ScriptedProtocol.unused, "\(id): request count")

        for (index, actual) in sent.enumerated() {
            let specification = try XCTUnwrap(exchanges[index]["request"] as? [String: Any])
            let where_ = "\(id) request \(index)"

            XCTAssertEqual(actual.method, specification["method"] as? String, where_)
            XCTAssertEqual(actual.url, specification["url"] as? String, where_)

            if let required = specification["headers"] as? [String: String] {
                for (header, value) in required {
                    XCTAssertEqual(actual.header(header), value, "\(where_): \(header)")
                }
            }

            for header in specification["headers_absent"] as? [String] ?? [] {
                XCTAssertNil(
                    actual.header(header),
                    "\(where_): \(header) should not have been sent"
                )
            }

            if let encoded = specification["body_base64"] as? String {
                XCTAssertEqual(actual.body, try data(encoded), where_)
            }

            if let fields = specification["body_json_has"] as? [String: String] {
                let parsed = try JSONSerialization.jsonObject(with: actual.body)
                let object = try XCTUnwrap(parsed as? [String: Any])
                for (field, value) in fields {
                    XCTAssertEqual(object[field] as? String, value, "\(where_): \(field)")
                }
            }

            for field in specification["body_json_lacks"] as? [String] ?? [] {
                let parsed = try JSONSerialization.jsonObject(with: actual.body)
                let object = try XCTUnwrap(parsed as? [String: Any])
                XCTAssertNil(
                    object[field],
                    "\(where_): the body carries \(field), which is the guard being tested"
                )
            }
        }
    }

    // MARK: - helpers

    private func flavour(_ name: String) throws -> HTTPProvider.Flavour {
        switch name {
        case "self_hosted": return .selfHosted
        case "github": return .gitHub
        case "gitlab": return .gitLab
        default:
            XCTFail("unknown flavour \(name)")
            throw Failure.unknownFlavour(name)
        }
    }

    private func body(_ vector: [String: Any]) throws -> Data {
        try data(vector["body_base64"] as? String)
    }

    private func expectedRevision(_ vector: [String: Any]) -> String? {
        vector["expected_revision"] as? String
    }

    private func data(_ encoded: String?) throws -> Data {
        guard let encoded, !encoded.isEmpty else { return Data() }
        guard let decoded = Data(base64Encoded: encoded) else {
            throw Failure.notBase64(encoded)
        }
        return decoded
    }

    private enum Failure: Error {
        case unknownFlavour(String)
        case notBase64(String)
        case vectorsNotFound(String)
    }

    /// Walks up from this source file to the repository root.
    private func loadVectors() throws -> [String: Any] {
        var directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        while directory.path != "/" {
            let candidate = directory
                .appendingPathComponent("conformance/vectors/sync-provider.json")
            if FileManager.default.fileExists(atPath: candidate.path) {
                let parsed = try JSONSerialization.jsonObject(with: Data(contentsOf: candidate))
                guard let object = parsed as? [String: Any] else {
                    throw Failure.vectorsNotFound(candidate.path)
                }
                return object
            }
            directory = directory.deletingLastPathComponent()
        }
        throw Failure.vectorsNotFound(#filePath)
    }
}

/// Answers from a script and records what it was asked.
///
/// A `URLProtocol` rather than a local server: the GitHub and GitLab URLs are
/// hard-coded in the implementation, which is right, and a protocol can still
/// stand in for them.
final class ScriptedProtocol: URLProtocol {

    struct Recorded {
        let method: String
        let url: String
        let headers: [String: String]
        let body: Data

        /// Header lookup is case-insensitive, as HTTP headers are.
        func header(_ name: String) -> String? {
            headers.first { $0.key.caseInsensitiveCompare(name) == .orderedSame }?.value
        }
    }

    // URLProtocol instances are created by the system, so the script and the
    // record have to live outside them.
    private static let lock = NSLock()
    nonisolated(unsafe) private static var exchanges: [[String: Any]] = []
    nonisolated(unsafe) private static var next = 0
    nonisolated(unsafe) private static var recorded: [Recorded] = []

    static func script(_ exchanges: [[String: Any]]) {
        lock.lock()
        defer { lock.unlock() }
        Self.exchanges = exchanges
        next = 0
        recorded = []
    }

    static func reset() {
        script([])
    }

    static var seen: [Recorded] {
        lock.lock()
        defer { lock.unlock() }
        return recorded
    }

    static var unused: Int {
        lock.lock()
        defer { lock.unlock() }
        return exchanges.count - next
    }

    override class func canInit(with request: URLRequest) -> Bool { true }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        Self.lock.lock()

        // `URLSession` moves a body to `httpBodyStream` by the time a protocol
        // sees the request, so both have to be read.
        var body = request.httpBody ?? Data()
        if body.isEmpty, let stream = request.httpBodyStream {
            stream.open()
            var buffer = [UInt8](repeating: 0, count: 4096)
            while stream.hasBytesAvailable {
                let read = stream.read(&buffer, maxLength: buffer.count)
                if read <= 0 { break }
                body.append(contentsOf: buffer[0..<read])
            }
            stream.close()
        }

        Self.recorded.append(Recorded(
            method: request.httpMethod ?? "GET",
            url: request.url?.absoluteString ?? "",
            headers: request.allHTTPHeaderFields ?? [:],
            body: body
        ))

        guard Self.next < Self.exchanges.count else {
            Self.lock.unlock()
            client?.urlProtocol(
                self,
                didFailWithError: NSError(
                    domain: "ScriptedProtocol",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey:
                        "the implementation made more requests than the case scripts"]
                )
            )
            return
        }

        let exchange = Self.exchanges[Self.next]
        Self.next += 1
        Self.lock.unlock()

        let scripted = exchange["response"] as? [String: Any] ?? [:]
        let status = scripted["status"] as? Int ?? 500
        var headers = scripted["headers"] as? [String: String] ?? [:]

        let payload: Data
        if let json = scripted["body_json"] {
            payload = (try? JSONSerialization.data(withJSONObject: json)) ?? Data()
            headers["Content-Type"] = "application/json"
        } else if let encoded = scripted["body_base64"] as? String, !encoded.isEmpty {
            payload = Data(base64Encoded: encoded) ?? Data()
        } else {
            payload = Data()
        }

        let response = HTTPURLResponse(
            url: request.url ?? URL(fileURLWithPath: "/"),
            statusCode: status,
            httpVersion: "HTTP/1.1",
            headerFields: headers
        )!

        client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
        if !payload.isEmpty {
            client?.urlProtocol(self, didLoad: payload)
        }
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}
