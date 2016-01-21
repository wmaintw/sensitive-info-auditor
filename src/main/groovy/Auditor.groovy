import groovy.time.TimeCategory
import groovy.util.logging.Slf4j
import groovyx.net.http.HttpResponseException
import groovyx.net.http.RESTClient

import java.util.concurrent.Executors

import static org.apache.commons.lang3.StringUtils.containsIgnoreCase

@Slf4j
class Auditor {
    def reportDate = new Date()
    def THREADS = 2
    def users = this.getClass().getResource("github-accounts.txt").readLines()
    def sensitiveWords = this.getClass().getResource("sensitive-words.txt").readLines()
    def token = this.getClass().getResource("oauth-token.txt").readLines().get(0)

    static def main(args) {
        def auditor = new Auditor()

        def startDate = new Date()
        log("Start auditing, ${startDate}")

        auditor.doAudit()

        def finishDate = new Date()
        use(TimeCategory) {
            def duration = finishDate - startDate
            log("Done, duration: ${duration}")
        }
    }

    def doAudit() {
        log("${users.size()} users' repo to be audited")

        def allUsersRepos = reposOfEveryone(users)

        def auditEveryRepo = { user, repos ->
            log("[${Thread.currentThread().getName()}] start to scan ${user}'s repos, ${repos.size} in total")
            auditEveryRepo(user, repos)
        }

        def pool = Executors.newFixedThreadPool(THREADS)

        try {
            def futures = allUsersRepos.collect { entry ->
                pool.submit({ ->
                    auditEveryRepo entry.key, entry.value
                } as Runnable)
            }
            futures.each { it.get() }
        } finally {
            pool.shutdown()
        }
    }

    def auditEveryRepo(user, repos) {
        repos.eachWithIndex { repo, repoIndex ->
            log("[${user}] scanning repo: ${repo.name}, (${repoIndex + 1} of ${repos.size()})")

            def commitsPath = "/repos/${user}/${repo.name}/commits"
            log.debug(commitsPath)
            def commits = requestApi(commitsPath)
            log("[${user}] [${repo.name}] ${commits.size} commit in total")

            auditEveryCommit(user, repo, commits)
        }
    }

    def auditEveryCommit(user, repo, commits) {
        commits.eachWithIndex { commitObject, commitIndex ->
            log("[${user}] [${repo.name}] ${commitIndex + 1}/${commits.size} commit")

            def singleCommit = requestApi("/repos/${user}/${repo.name}/commits/${commitObject.sha}")

            def violations = detectSensitiveInfo(singleCommit.commit.message)
            if (isExist(violations)) {
                recordTheseViolations([user: user, repo: repo.name, commit: singleCommit.sha, violations: violations,
                                       type: "message", content: singleCommit.commit.message,
                                       fileBlobUrl:"", commitHtmlUrl:singleCommit.html_url])
            }

            singleCommit.files.each { file ->
                detectByFilename(file, user, repo.name, singleCommit)
                detectByContent(file, user, repo.name, singleCommit)
            }
        }
    }

    private void detectByFilename(file, user, repoName, singleCommit) {
        def violations = detectSensitiveInfo(file.filename)
        if (isExist(violations)) {
            recordTheseViolations([user: user, repo: repoName, commit: singleCommit.sha, violations: violations,
                                   type: "filename", filename: file.filename, content: file.patch,
                                   fileBlobUrl:file.blob_url, commitHtmlUrl:singleCommit.html_url])
        }
    }

    private void detectByContent(file, user, repoName, singleCommit) {
        def violations = detectSensitiveInfo(file.patch)
        if (isExist(violations)) {
            recordTheseViolations([user: user, repo: repoName, commit: singleCommit.sha, violations: violations,
                                   type: "file", filename: file.filename, content: file.patch,
                                   fileBlobUrl:file.blob_url, commitHtmlUrl:singleCommit.html_url])
        }
    }

    def isExist(List violations) {
        violations.size() > 0
    }

    synchronized recordTheseViolations(recordContent) {
        def warningsFilePath = new File("scan-report/${reportDate.time}")
        if (!warningsFilePath.exists()) {
            warningsFilePath.mkdirs()
        }

        new File(warningsFilePath, "${recordContent.user}.txt") << "${recordContent} \n\n"
    }

    def detectSensitiveInfo(content) {
        if (content == null) {
            return []
        }

        def violation = []

        sensitiveWords.each { keyword ->
            if (containsIgnoreCase(content, keyword)) {
                violation.add(keyword)
            }
        }

        violation
    }

    def reposOfEveryone(users) {
        def repos = [:]

        users.eachWithIndex { user, index ->
            println "${index + 1} / ${users.size()} fetching ${user}'s repos."
            repos["${user}"] = reposOfUser(user)
        }

        repos
    }

    def reposOfUser(user) {
        def repos = requestApi("/users/${user}/repos")
        repos.grep { it.fork == false }
    }

    def requestApi(path) {
        requestApi(path, [:])
    }

    def requestApi(path, query) {
        def userPassBase64 = "${token}:x-oauth-basic".toString().bytes.encodeBase64()
        def data = []

        // for github rate limit consideration
        Thread.sleep(400)

        try {
            data = apiClient().get(path: path, query: query, headers: ['Authorization': "Basic ${userPassBase64}",
                                                            'Accept'       : 'application/json',
                                                            'User-Agent'   : 'Apache HTTPClient']).data
        } catch (HttpResponseException e) {
            log("[WARNING] HttpResponseException occurred, the reason might be the repo is empty, or rate limit, skip this one. Detailed error message: ${e.message}")
            log("[WARNING] path: ${path}, query: ${query}, skipped.")
        }

        data
    }

    def RESTClient apiClient() {
        def client = new RESTClient("https://api.github.com/")
        client.ignoreSSLIssues()

        client
    }

    private static log(GString logMessage) {
        println "${new Date()} ${logMessage}"
    }
}
