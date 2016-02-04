import groovyx.net.http.HttpResponseException
import groovyx.net.http.RESTClient

import static CommandLineLogger.log

class GithubApiClient {

    private static final String GITHUB_API_BASE_URL = "https://api.github.com/"
    private static final int TIME_INTERVAL = 300

    def token = this.getClass().getResource("oauth-token.txt").readLines().get(0)

    def fetchRepos(user) {
        request("/users/${user}/repos")
    }

    def fetchCommits(user, repoName) {
        request("/repos/${user}/${repoName}/commits")
    }

    def fetchSingleCommit(user, repoName, commitSha) {
        request("/repos/${user}/${repoName}/commits/${commitSha}")
    }

    def fetchApiRateLimit() {
        request("/rate_limit")
    }

    def request(path) {
        request(path, [:])
    }

    def request(path, query) {
        def userPassBase64 = "${token}:x-oauth-basic".toString().bytes.encodeBase64()
        def data = []

        // for github rate limit consideration
        Thread.sleep(TIME_INTERVAL)

        try {
            data = restClient().get(path: path, query: query, headers: ['Authorization': "Basic ${userPassBase64}",
                                                                       'Accept'       : 'application/json',
                                                                       'User-Agent'   : 'Apache HTTPClient']).data
        } catch (HttpResponseException e) {
            log("[WARNING] HttpResponseException occurred, the reason might be the repo is empty, or rate limit, skip this one. Detailed error message: ${e.message}")
            log("[WARNING] path: ${path}, query: ${query}, skipped.")
        }

        data
    }

    def restClient() {
        def client = new RESTClient(GITHUB_API_BASE_URL)
        client.ignoreSSLIssues()

        client
    }
}
