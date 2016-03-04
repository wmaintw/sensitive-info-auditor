package github

import model.RateLimitation
import utils.ApiClient

import static utils.AccountType.USER
import static utils.CommandLineLogger.log

class GithubApiClient {
    private ApiClient apiClient = new ApiClient()

    def fetchPublicNoneForkedReposInBatch(users) {
        def repos = [:]

        users.eachWithIndex { user, index ->
            log("${index + 1} / ${users.size()} fetching ${user}'s repos.")
            repos["${user}"] = this.fetchPublicNoneForkedRepos(user)
        }

        repos
    }

    def fetchPublicNoneForkedRepos(user) {
        def repos = this.fetchRepos(user)
        repos.grep { it.fork == false }
    }

    def fetchRateLimitCurrentStatus() {
        def limitation = this.fetchApiRateLimitRawData()
        def remaining = limitation.resources.core.remaining
        def resetDate = new Date((limitation.resources.core.reset as long) * 1000)

        new RateLimitation(remaining as int, resetDate)
    }

    def fetchRepos(user) {
        apiClient.request("/users/${user}/repos")
    }

    def fetchCommits(user, repoName) {
        apiClient.request("/repos/${user}/${repoName}/commits")
    }

    def fetchSingleCommit(user, repoName, commitSha) {
        apiClient.request("/repos/${user}/${repoName}/commits/${commitSha}")
    }

    def fetchApiRateLimitRawData() {
        apiClient.request("/rate_limit")
    }

    def fetchAccount(accountName) {
        apiClient.request("/users/${accountName}")
    }

    def fetchUsersFromOrganization(String orgName) {
        def allUsers = []
        def fetchedUsers = []
        def pageIndex = 1;

        while (true) {
            log("Fetching members in batch: ${pageIndex}")
            fetchedUsers = apiClient.request("/orgs/${orgName}/members", [page: pageIndex++])
            if (fetchedUsers.isEmpty()) {
                break;
            }
            allUsers.addAll(fetchedUsers)
        }

        allUsers.grep { USER.name().equalsIgnoreCase(it.type) }
    }
}
