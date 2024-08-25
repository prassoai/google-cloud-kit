import Foundation
import NIOHTTP1
import AsyncHTTPClient
import Foundation
import NIO

struct ImpersonateTokenResponse: Decodable {
    let accessToken: String
    let expireTime: String
}

public class OAuthImpersonatedServiceAccount: OAuthRefreshable {
    let httpClient: HTTPClient
    let credentials: ImpersonatedServiceAccountCredentials
    let tokenLifetimeSeconds: Int?
    public let scope: String
    private let decoder = JSONDecoder()
    private let eventLoop: EventLoop

    init(credentials: ImpersonatedServiceAccountCredentials, scopes: [GoogleCloudAPIScope], httpClient: HTTPClient, eventLoop: EventLoop, tokenLifetimeSeconds: Int? = nil) {
        self.credentials = credentials
        self.scope = scopes.map { $0.value }.joined(separator: " ")
        self.httpClient = httpClient
        self.eventLoop = eventLoop
        self.tokenLifetimeSeconds = tokenLifetimeSeconds
        decoder.keyDecodingStrategy = .convertFromSnakeCase
    }

    public func refresh() -> EventLoopFuture<OAuthAccessToken> {

        let tokenRefresher = OAuthApplicationDefault(
            clientId: credentials.sourceCredentials.clientId,
            clientSecret: credentials.sourceCredentials.clientSecret,
            refreshToken: credentials.sourceCredentials.refreshToken,
            httpClient: httpClient,
            eventLoop: eventLoop)
        
        // Use flatMap to handle the future returned by tokenRefresher.refresh()
        return tokenRefresher.refresh().flatMap { accessToken in
            do {
                // Construct the request body
                let lifetimeString = "\(self.tokenLifetimeSeconds ?? 3600)s"
                let requestBody: [String: Any] = [
                    "lifetime": lifetimeString,
                    "scope": self.scope,
                    "delegates": self.credentials.delegates
                ]
                
                let requestBodyData = try JSONSerialization.data(withJSONObject: requestBody, options: [])
                
                // Prepare the HTTP request
                let authToken = "Bearer \(accessToken.accessToken)"
                let headers: HTTPHeaders = ["Content-Type": "application/json", "Authorization": authToken]
                
                let request = try HTTPClient.Request(
                    url: self.credentials.serviceAccountImpersonationUrl,
                    method: .POST,
                    headers: headers,
                    body: .data(requestBodyData)
                )
                
                // Execute the request
                return self.httpClient.execute(request: request, eventLoop: .delegate(on: self.eventLoop)).flatMap { response in
                    
                    guard var byteBuffer = response.body,
                          let responseData = byteBuffer.readData(length: byteBuffer.readableBytes),
                          response.status == .ok else {
                        return self.eventLoop.makeFailedFuture(OauthRefreshError.noResponse(response.status))
                    }
                    
                    do {
                        let accessTokenResponse = try self.decoder.decode(ImpersonateTokenResponse.self, from: responseData)
                        // Parse expiry time
                        guard let expiry = ISO8601DateFormatter().date(from: accessTokenResponse.expireTime) else {
                            return self.eventLoop.makeFailedFuture(OauthRefreshError.invalidExpiryDate)
                        }
                        let currentDate = Date()
                        let expiresIn = Int(expiry.timeIntervalSince(currentDate))
                        
                        let oauthAccessToken = OAuthAccessToken(
                            accessToken: accessTokenResponse.accessToken,
                            tokenType: "Bearer",
                            expiresIn: expiresIn
                        )
                        
                        return self.eventLoop.makeSucceededFuture(oauthAccessToken)
                    } catch {
                        return self.eventLoop.makeFailedFuture(error)
                    }
                }
            } catch {
                return self.eventLoop.makeFailedFuture(error)
            }
        }
    }

}
