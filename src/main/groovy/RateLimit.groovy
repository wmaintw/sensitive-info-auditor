import groovyx.net.http.RESTClient

class RateLimit {
    def token = this.getClass().getResource("oauth-token.txt").readLines().get(0)

    static def main(args) {
        def instance = new RateLimit()
        instance.getRateLimit()
    }

    def getRateLimit() {
        def userPassBase64 = "${token}:x-oauth-basic".toString().bytes.encodeBase64()
        def limitation = apiClient().get(path: '/rate_limit', headers: ['Authorization': "Basic ${userPassBase64}",
                                                                           'Accept'       : 'application/json',
                                                                           'User-Agent'   : 'Apache HTTPClient']).data
        println(limitation.resources.core.limit)
        println(limitation.resources.core.remaining)
        println(new Date((limitation.resources.core.reset as long) * 1000))
    }

    def RESTClient apiClient() {
        def client = new RESTClient("https://api.github.com/")
        client.ignoreSSLIssues()

        client
    }
}
