import Foundation

/// GitHub, GitLab and the self-hosted server.
///
/// All three are "a file with a revision" over HTTP; they differ only in the
/// shape of the request and in what they call the revision:
///
/// | Target | Revision | Guarded write |
/// |---|---|---|
/// | self-hosted | ETag | `If-Match`, `412` when stale |
/// | GitHub | blob `sha` | `sha` in the JSON body, `409` when stale |
/// | GitLab | `last_commit_id` | `last_commit_id` in the body, `400`/`409` |
///
/// Tokens are read from the Keychain at the point of use and never stored in
/// the vault, because the vault's settings travel to the other devices.
struct HTTPProvider: SyncProvider {
    enum Flavour: Sendable {
        /// `location` is the server's base URL.
        case selfHosted
        /// `location` is `owner/repo/branch`.
        case gitHub
        /// `location` is `project-id/branch` (the numeric project id is what
        /// the API wants; a path would have to be URL-encoded on every call).
        case gitLab
    }

    let flavour: Flavour
    let location: String
    let token: String
    let session: URLSession = .shared

    func fetch(_ name: String) async throws -> (bytes: Data, revision: String)? {
        switch flavour {
        case .selfHosted: try await fetchSelfHosted(name)
        case .gitHub: try await fetchGitHub(name)
        case .gitLab: try await fetchGitLab(name)
        }
    }

    func put(_ name: String, bytes: Data, ifRevision expected: String?) async throws -> String? {
        switch flavour {
        case .selfHosted: try await putSelfHosted(name, bytes, expected)
        case .gitHub: try await putGitHub(name, bytes, expected)
        case .gitLab: try await putGitLab(name, bytes, expected)
        }
    }

    // MARK: - self-hosted

    private func fetchSelfHosted(_ name: String) async throws -> (bytes: Data, revision: String)? {
        var request = URLRequest(url: try selfHostedURL(name))
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")

        let (data, response) = try await session.data(for: request)
        let http = try httpResponse(response)
        if http.statusCode == 404 { return nil }
        try expect(http, data, oneOf: [200])

        guard let etag = http.value(forHTTPHeaderField: "ETag")?.trimmingCharacters(in: ["\""])
        else { throw SyncProviderError.server(200, "the response had no ETag") }
        return (data, etag)
    }

    private func putSelfHosted(_ name: String, _ bytes: Data, _ expected: String?) async throws -> String? {
        var request = URLRequest(url: try selfHostedURL(name))
        request.httpMethod = "PUT"
        request.httpBody = bytes
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        if let expected {
            request.setValue("\"\(expected)\"", forHTTPHeaderField: "If-Match")
        } else {
            request.setValue("*", forHTTPHeaderField: "If-None-Match")
        }

        let (data, response) = try await session.data(for: request)
        let http = try httpResponse(response)
        // 412 is the server saying someone wrote first; that is a retry, not
        // an error to show the user.
        if http.statusCode == 412 { return nil }
        try expect(http, data, oneOf: [200, 204])
        return http.value(forHTTPHeaderField: "ETag")?.trimmingCharacters(in: ["\""])
            ?? Revision.of(bytes)
    }

    private func selfHostedURL(_ name: String) throws -> URL {
        guard let base = URL(string: location),
              base.scheme == "https" || base.scheme == "http"
        else { throw SyncProviderError.notConfigured("“\(location)” is not a URL") }
        return base.appendingPathComponent("v1/files/\(name)")
    }

    // MARK: - GitHub

    private func fetchGitHub(_ name: String) async throws -> (bytes: Data, revision: String)? {
        let (owner, repo, branch) = try gitHubLocation()
        var components = URLComponents(string: "https://api.github.com/repos/\(owner)/\(repo)/contents/\(name)")
        components?.queryItems = [URLQueryItem(name: "ref", value: branch)]
        guard let url = components?.url else {
            throw SyncProviderError.notConfigured("“\(location)” is not a repository")
        }

        var request = URLRequest(url: url)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")

        let (data, response) = try await session.data(for: request)
        let http = try httpResponse(response)
        if http.statusCode == 404 { return nil }
        try expect(http, data, oneOf: [200])

        struct Contents: Decodable {
            let sha: String
            let content: String
            let encoding: String
        }
        let contents = try JSONDecoder().decode(Contents.self, from: data)
        guard contents.encoding == "base64",
              let bytes = Data(base64Encoded: contents.content, options: [.ignoreUnknownCharacters])
        else { throw SyncProviderError.server(200, "the file came back in an unexpected encoding") }

        return (bytes, contents.sha)
    }

    private func putGitHub(_ name: String, _ bytes: Data, _ expected: String?) async throws -> String? {
        let (owner, repo, branch) = try gitHubLocation()
        guard let url = URL(string: "https://api.github.com/repos/\(owner)/\(repo)/contents/\(name)")
        else { throw SyncProviderError.notConfigured("“\(location)” is not a repository") }

        var body: [String: String] = [
            "message": "MFA sync",
            "content": bytes.base64EncodedString(),
            "branch": branch,
        ]
        // Without `sha` GitHub refuses to overwrite, which is the guard we
        // want on a first write.
        if let expected { body["sha"] = expected }

        var request = URLRequest(url: url)
        request.httpMethod = "PUT"
        request.httpBody = try JSONEncoder().encode(body)
        request.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        request.setValue("2022-11-28", forHTTPHeaderField: "X-GitHub-Api-Version")

        let (data, response) = try await session.data(for: request)
        let http = try httpResponse(response)
        // 409 is a stale sha; 422 is "already exists" on a create.
        if http.statusCode == 409 || http.statusCode == 422 { return nil }
        try expect(http, data, oneOf: [200, 201])

        struct Written: Decodable {
            struct Content: Decodable { let sha: String }
            let content: Content
        }
        return try JSONDecoder().decode(Written.self, from: data).content.sha
    }

    private func gitHubLocation() throws -> (owner: String, repo: String, branch: String) {
        let parts = location.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard parts.count >= 2 else {
            throw SyncProviderError.notConfigured("expected owner/repo or owner/repo/branch")
        }
        return (parts[0], parts[1], parts.count > 2 ? parts[2] : "main")
    }

    // MARK: - GitLab

    private func fetchGitLab(_ name: String) async throws -> (bytes: Data, revision: String)? {
        let (project, branch) = try gitLabLocation()
        let path = encoded(name)
        var components = URLComponents(string: "https://gitlab.com/api/v4/projects/\(encoded(project))/repository/files/\(path)")
        components?.queryItems = [URLQueryItem(name: "ref", value: branch)]
        guard let url = components?.url else {
            throw SyncProviderError.notConfigured("“\(location)” is not a project")
        }

        var request = URLRequest(url: url)
        request.setValue(token, forHTTPHeaderField: "PRIVATE-TOKEN")

        let (data, response) = try await session.data(for: request)
        let http = try httpResponse(response)
        if http.statusCode == 404 { return nil }
        try expect(http, data, oneOf: [200])

        struct File: Decodable {
            let content: String
            let encoding: String
            let last_commit_id: String
        }
        let file = try JSONDecoder().decode(File.self, from: data)
        guard file.encoding == "base64",
              let bytes = Data(base64Encoded: file.content, options: [.ignoreUnknownCharacters])
        else { throw SyncProviderError.server(200, "the file came back in an unexpected encoding") }

        return (bytes, file.last_commit_id)
    }

    private func putGitLab(_ name: String, _ bytes: Data, _ expected: String?) async throws -> String? {
        let (project, branch) = try gitLabLocation()
        guard let url = URL(string: "https://gitlab.com/api/v4/projects/\(encoded(project))/repository/files/\(encoded(name))")
        else { throw SyncProviderError.notConfigured("“\(location)” is not a project") }

        var body: [String: String] = [
            "branch": branch,
            "content": bytes.base64EncodedString(),
            "encoding": "base64",
            "commit_message": "MFA sync",
        ]
        if let expected { body["last_commit_id"] = expected }

        var request = URLRequest(url: url)
        // POST creates, PUT updates; GitLab is strict about which.
        request.httpMethod = expected == nil ? "POST" : "PUT"
        request.httpBody = try JSONEncoder().encode(body)
        request.setValue(token, forHTTPHeaderField: "PRIVATE-TOKEN")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await session.data(for: request)
        let http = try httpResponse(response)
        // 400 covers a stale last_commit_id and "already exists" on a create.
        if http.statusCode == 400 || http.statusCode == 409 { return nil }
        try expect(http, data, oneOf: [200, 201])

        // The write response does not carry the new commit id, so read it back.
        return try await fetchGitLab(name)?.revision
    }

    private func gitLabLocation() throws -> (project: String, branch: String) {
        let parts = location.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
        guard let project = parts.first else {
            throw SyncProviderError.notConfigured("expected a project id, optionally /branch")
        }
        return (project, parts.count > 1 ? parts[1] : "main")
    }

    private func encoded(_ value: String) -> String {
        value.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? value
    }

    // MARK: - shared

    private func httpResponse(_ response: URLResponse) throws -> HTTPURLResponse {
        guard let http = response as? HTTPURLResponse else {
            throw SyncProviderError.server(0, "the response was not HTTP")
        }
        return http
    }

    private func expect(_ http: HTTPURLResponse, _ data: Data, oneOf accepted: [Int]) throws {
        guard !accepted.contains(http.statusCode) else { return }
        // Only the first line, and never the request: an error body can echo
        // headers, and the token is in one of them.
        let detail = String(data: data.prefix(200), encoding: .utf8)?
            .split(separator: "\n").first.map(String.init) ?? ""
        throw SyncProviderError.server(http.statusCode, detail)
    }
}
