import groovyx.net.http.RESTClient

class RateLimit {
    def token = this.getClass().getResource("oauth-token.txt").readLines().get(0)

    static def main(args) {
        def instance = new RateLimit()
        instance.getRateLimit()
    }

    def getRateLimit() {
        def userPassBase64 = "${token}:x-oauth-basic".toString().bytes.encodeBase64()
        def resp = apiClient().get(path: '/users/wmaintw/repos', headers: ['Authorization': "Basic ${userPassBase64}",
                                                                           'Accept'       : 'application/json',
                                                                           'User-Agent'   : 'Apache HTTPClient'])
        println(resp.headers.'X-RateLimit-Limit')
        println(resp.headers.'X-RateLimit-Remaining')

        def rateResetDate = resp.headers.'X-RateLimit-Reset'
        println(rateResetDate)
        println(new Date((rateResetDate as long) * 1000))
    }

    def RESTClient apiClient() {
        def client = new RESTClient("https://api.github.com/")
        client.ignoreSSLIssues()

        client
    }
}
