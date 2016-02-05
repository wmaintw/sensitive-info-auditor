package audit

import github.GithubApiClient
import model.Findings
import model.MatchedSensitiveWords

import java.util.concurrent.Executors

import static org.apache.commons.lang3.StringUtils.containsIgnoreCase
import static utils.CommandLineLogger.log
import static utils.WhereSensitiveWordsFound.*

class Auditor {
    def THREADS = 2
    def users = this.getClass().getResource("../github-accounts.txt").readLines()
    def generalSensitiveWords = this.getClass().getResource("../sensitive-words-general.txt").readLines()
    def clientSpecificSensitiveWords = this.getClass().getResource("../sensitive-words.txt").readLines()

    def apiClient = new GithubApiClient()
    def reporter = new SensitiveInfoReporter()

    def doAudit() {
        log("${users.size()} users' repo to be audited")

        def allUsersRepos = apiClient.fetchPublicNoneForkedReposInBatch(users)

        def auditEveryRepoClosure = { user, repos ->
            log("[${Thread.currentThread().getName()}] start to scan ${user}'s repos, ${repos.size} in total")
            auditEveryRepo(user, repos)
        }
        startAuditUsingMultipleThreads(allUsersRepos, auditEveryRepoClosure)

        generateReports()
    }

    def void startAuditUsingMultipleThreads(LinkedHashMap allUsersRepos, auditEveryRepoClosure) {
        def pool = Executors.newFixedThreadPool(THREADS)

        try {
            def futures = allUsersRepos.collect { entry ->
                pool.submit({ ->
                    auditEveryRepoClosure entry.key, entry.value
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

            def commits = apiClient.fetchCommits(user, repo.name)
            log("[${user}] [${repo.name}] ${commits.size} commit in total")

            auditEveryCommit(user, repo.name, commits)
        }
    }

    def auditEveryCommit(user, repoName, commits) {
        commits.eachWithIndex { commitObject, commitIndex ->
            log("[${user}] [${repoName}] ${commitIndex + 1}/${commits.size} commit")

            def singleCommit = apiClient.fetchSingleCommit(user, repoName, commitObject.sha)
            auditCommitMessage(user, repoName, singleCommit)
            auditFilesWithinTheCommit(user, repoName, singleCommit)
        }
    }

    def auditCommitMessage(user, repoName, singleCommit) {
        def matchedSensitiveWords = detectSensitiveInfo(singleCommit.commit.message)
        if (matchedSensitiveWords.isFound()) {
            reporter.storeFindings(sensitiveInfoFoundInCommitMessage(user, repoName, matchedSensitiveWords, singleCommit))
        }
    }

    def auditFilesWithinTheCommit(user, repoName, singleCommit) {
        singleCommit.files.each { file ->
            detectSensitiveInfoInFilename(file, user, repoName, singleCommit)
            detectSensitiveInfoInFileContent(file, user, repoName, singleCommit)
        }
    }

    def void detectSensitiveInfoInFilename(file, user, repoName, singleCommit) {
        def matchedSensitiveWords = detectSensitiveInfo(file.filename)
        if (matchedSensitiveWords.isFound()) {
            reporter.storeFindings(sensitiveInfoFoundInFile(user, repoName, matchedSensitiveWords, Filename, file, singleCommit))
        }
    }

    def void detectSensitiveInfoInFileContent(file, user, repoName, singleCommit) {
        def matchedSensitiveWords = detectSensitiveInfo(file.patch)
        if (matchedSensitiveWords.isFound()) {
            reporter.storeFindings(sensitiveInfoFoundInFile(user, repoName, matchedSensitiveWords, FileContent, file, singleCommit))
        }
    }

    def MatchedSensitiveWords detectSensitiveInfo(content) {
        if (content == null) {
            return []
        }

        def matchedSensitiveWords = new MatchedSensitiveWords()

        generalSensitiveWords.each { keyword ->
            if (containsIgnoreCase(content, keyword)) {
                matchedSensitiveWords.generalSensitiveWords.add(keyword)
            }
        }

        clientSpecificSensitiveWords.each { keyword ->
            if (containsIgnoreCase(content, keyword)) {
                matchedSensitiveWords.clientSpecificSensitiveWords.add(keyword)
            }
        }

        matchedSensitiveWords
    }


    def sensitiveInfoFoundInCommitMessage(user, repoName, matchedSensitiveWords, singleCommit) {
        createFindings(user, repoName, singleCommit.sha, matchedSensitiveWords, CommitMessage,
                singleCommit.commit.message, "", singleCommit.html_url)
    }

    def sensitiveInfoFoundInFile(user, repoName, matchedSensitiveWords, whereTheSensitiveWordsFound, file, singleCommit) {
        createFindings(user, repoName, singleCommit.sha, matchedSensitiveWords, whereTheSensitiveWordsFound,
                file.filename, file.blob_url, singleCommit.html_url)
    }

    def createFindings(user, repoName, commitSha, matchedSensitiveWords, whereTheSensitiveWordsFound, filename, fileBlobUrl, commitHtmlUrl) {
        def findings = new Findings()
        findings.user = user
        findings.repoName = repoName
        findings.commitSha = commitSha
        findings.matchedSensitiveWords = matchedSensitiveWords
        findings.whereTheSensitiveWordsFound = whereTheSensitiveWordsFound
        findings.filename = filename
        findings.fileBlobUrl = fileBlobUrl
        findings.commitHtmlUrl = commitHtmlUrl

        findings
    }

    def checkApiRateLimit() {
        def status = apiClient.fetchRateLimitCurrentStatus()
        log("API rate limit remaining: ${status.remaining}, reset date: ${status.resetDate}")
    }

    def generateReports() {
        log("Generating summary report")
        reporter.generateSummaryReport()
    }
}
