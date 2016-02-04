import groovy.util.logging.Slf4j

import java.util.concurrent.Executors

import static CommandLineLogger.log
import static WhereViolationFound.*
import static org.apache.commons.lang3.StringUtils.containsIgnoreCase

@Slf4j
class Auditor {
    public static final String VIOLATION_WORDS_SEPERATOR = ' | '
    public static final String REPORT_HEADER = "Account, Repo, Possible sensitive info found, " +
            "Places where the possible sensitive info was found, " +
            "Filename or Commit message, Commit html url, Commit SHA \n"

    def reportDate = new Date()
    def THREADS = 2
    def users = this.getClass().getResource("github-accounts.txt").readLines()
    def sensitiveWords = this.getClass().getResource("sensitive-words.txt").readLines()
    def token = this.getClass().getResource("oauth-token.txt").readLines().get(0)
    def apiClient = new ApiClient()

    def doAudit() {
        log("${users.size()} users' repo to be audited")

        def allUsersRepos = fetchReposOfEveryone(users)

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
            checkApiRateLimit()

            def commitsPath = "/repos/${user}/${repo.name}/commits"
            log.debug(commitsPath)
            def commits = apiClient.request(commitsPath)
            log("[${user}] [${repo.name}] ${commits.size} commit in total")

            auditEveryCommit(user, repo, commits)
        }
    }

    def auditEveryCommit(user, repo, commits) {
        commits.eachWithIndex { commitObject, commitIndex ->
            log("[${user}] [${repo.name}] ${commitIndex + 1}/${commits.size} commit")

            def singleCommit = apiClient.request("/repos/${user}/${repo.name}/commits/${commitObject.sha}")

            def violations = detectSensitiveInfo(singleCommit.commit.message)
            if (isExist(violations)) {
                recordTheseViolations(commitMessageViolation(user, repo.name, violations, singleCommit))
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
            recordTheseViolations(fileViolation(user, repoName, violations, Filename, file, singleCommit))
        }
    }

    private void detectByContent(file, user, repoName, singleCommit) {
        def violations = detectSensitiveInfo(file.patch)
        if (isExist(violations)) {
            recordTheseViolations(fileViolation(user, repoName, violations, FileContent, file, singleCommit))
        }
    }

    def isExist(List violations) {
        violations.size() > 0
    }

    synchronized recordTheseViolations(violationRecord) {
        def warningsFilePath = new File("scan-report/${reportDate.time}")
        if (!warningsFilePath.exists()) {
            warningsFilePath.mkdirs()
        }

        def reportFileForEachAccount = new File(warningsFilePath, "${violationRecord.user}.csv")
        buildHeaderLine(reportFileForEachAccount)
        appendToReportFile(reportFileForEachAccount, violationRecord)
    }

    def commitMessageViolation(user, repoName, violations, singleCommit) {
        newViolation(user, repoName, singleCommit.sha, violations, CommitMessage, singleCommit.commit.message, "", singleCommit.html_url)
    }

    def fileViolation(user, repoName, violations, whereTheViolationFound, file, singleCommit) {
        newViolation(user, repoName, singleCommit.sha, violations, whereTheViolationFound, file.filename, file.blob_url, singleCommit.html_url)
    }

    def newViolation(user, repoName, commitSha, violations, violationType, filename, fileBlobUrl, commitHtmlUrl) {
        [user       : user, repo: repoName, commit: commitSha, violations: violations,
         type       : violationType, filename: filename,
         fileBlobUrl: fileBlobUrl, commitHtmlUrl: commitHtmlUrl]
    }

    def void buildHeaderLine(File reportFileForEachAccount) {
        if (!reportFileForEachAccount.exists()) {
            reportFileForEachAccount << REPORT_HEADER
        }
    }

    def File appendToReportFile(File reportFileForEachAccount, violationRecord) {
        reportFileForEachAccount << "${formatRecord(violationRecord)} \n"
    }

    def formatRecord(record) {
        "${record.user}, ${record.repo}, ${record.violations.join(VIOLATION_WORDS_SEPERATOR)}, ${record.type}, " +
                "${record.filename}, ${record.commitHtmlUrl}, ${record.commit}"
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

    def fetchReposOfEveryone(users) {
        def repos = [:]

        users.eachWithIndex { user, index ->
            log("${index + 1} / ${users.size()} fetching ${user}'s repos.")
            repos["${user}"] = fetchReposOfUser(user)
        }

        repos
    }

    def fetchReposOfUser(user) {
        def repos = apiClient.request("/users/${user}/repos")
        repos.grep { it.fork == false }
    }

    def checkApiRateLimit() {
        def limitation = apiClient.request("/rate_limit")
        def remaining = limitation.resources.core.remaining
        def resetDate = new Date((limitation.resources.core.reset as long) * 1000)
        log("API rate limit remaining: ${remaining}, reset date: ${resetDate}")
    }
}
