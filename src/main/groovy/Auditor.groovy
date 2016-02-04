import groovy.util.logging.Slf4j

import java.util.concurrent.Executors

import static CommandLineLogger.log
import static WhereSensitiveWordsFound.*
import static org.apache.commons.lang3.StringUtils.containsIgnoreCase

@Slf4j
class Auditor {
    public static final String WORDS_SEPERATOR = ' | '
    public static final String REPORT_HEADER = "Account, Repo, Possible sensitive info found, " +
            "Places where the possible sensitive info was found, " +
            "Filename or Commit message, Commit html url, Commit SHA \n"

    def reportDate = new Date()
    def THREADS = 2
    def users = this.getClass().getResource("github-accounts.txt").readLines()
    def sensitiveWords = this.getClass().getResource("sensitive-words.txt").readLines()
    def token = this.getClass().getResource("oauth-token.txt").readLines().get(0)
    def apiClient = new GithubApiClient()

    def doAudit() {
        log("${users.size()} users' repo to be audited")

        def allUsersRepos = fetchReposOfEveryone(users)

        def auditEveryRepoClosure = { user, repos ->
            log("[${Thread.currentThread().getName()}] start to scan ${user}'s repos, ${repos.size} in total")
            auditEveryRepo(user, repos)
        }
        startAuditUsingMultipleThreads(allUsersRepos, auditEveryRepoClosure)
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
        if (isExist(matchedSensitiveWords)) {
            storeFindings(sensitiveInfoFoundInCommitMessage(user, repoName, matchedSensitiveWords, singleCommit))
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
        if (isExist(matchedSensitiveWords)) {
            storeFindings(sensitiveInfoFoundInFile(user, repoName, matchedSensitiveWords, InFilename, file, singleCommit))
        }
    }

    def void detectSensitiveInfoInFileContent(file, user, repoName, singleCommit) {
        def matchedSensitiveWords = detectSensitiveInfo(file.patch)
        if (isExist(matchedSensitiveWords)) {
            storeFindings(sensitiveInfoFoundInFile(user, repoName, matchedSensitiveWords, InFileContent, file, singleCommit))
        }
    }

    def detectSensitiveInfo(content) {
        if (content == null) {
            return []
        }

        def matchedSensitiveWords = []

        sensitiveWords.each { keyword ->
            if (containsIgnoreCase(content, keyword)) {
                matchedSensitiveWords.add(keyword)
            }
        }

        matchedSensitiveWords
    }

    def isExist(sensitiveWordsFound) {
        sensitiveWordsFound.size() > 0
    }

    def sensitiveInfoFoundInCommitMessage(user, repoName, matchedSensitiveWords, singleCommit) {
        createFindings(user, repoName, singleCommit.sha, matchedSensitiveWords, InCommitMessage,
                singleCommit.commit.message, "", singleCommit.html_url)
    }

    def sensitiveInfoFoundInFile(user, repoName, matchedSensitiveWords, whereTheSensitiveWordsFound, file, singleCommit) {
        createFindings(user, repoName, singleCommit.sha, matchedSensitiveWords, whereTheSensitiveWordsFound,
                file.filename, file.blob_url, singleCommit.html_url)
    }

    def createFindings(user, repoName, commitSha, matchedSensitiveWords, whereTheSensitiveWordsFound, filename, fileBlobUrl, commitHtmlUrl) {
        [user: user, repo: repoName, commitSha: commitSha, matchedSensitiveWords: matchedSensitiveWords, whereTheSensitiveWordsFound: whereTheSensitiveWordsFound,
         filename: filename, fileBlobUrl: fileBlobUrl, commitHtmlUrl: commitHtmlUrl]
    }

    synchronized storeFindings(record) {
        def reportFilePath = new File("scan-report/${reportDate.time}")
        if (!reportFilePath.exists()) {
            reportFilePath.mkdirs()
        }

        def reportFileForEachUser = new File(reportFilePath, "${record.user}.csv")
        buildHeaderLine(reportFileForEachUser)
        appendToReportFile(reportFileForEachUser, record)
    }

    def void buildHeaderLine(File reportFile) {
        if (!reportFile.exists()) {
            reportFile << REPORT_HEADER
        }
    }

    def File appendToReportFile(File reportFile, record) {
        reportFile << "${formatFindings(record)} \n"
    }

    def formatFindings(record) {
        "${record.user}, ${record.repo}, ${record.matchedSensitiveWords.join(WORDS_SEPERATOR)}, ${record.whereTheSensitiveWordsFound}, " +
                "${record.filename}, ${record.commitHtmlUrl}, ${record.commitSha}"
    }

    def fetchReposOfEveryone(users) {
        def repos = [:]

        users.eachWithIndex { user, index ->
            log("${index + 1} / ${users.size()} fetching ${user}'s repos.")
            repos["${user}"] = fetchPublicNoneForkedRepos(user)
        }

        repos
    }

    def fetchPublicNoneForkedRepos(user) {
        def repos = apiClient.fetchRepos(user)
        repos.grep { it.fork == false }
    }

    def checkApiRateLimit() {
        def limitation = apiClient.fetchApiRateLimit()
        def remaining = limitation.resources.core.remaining
        def resetDate = new Date((limitation.resources.core.reset as long) * 1000)
        log("API rate limit remaining: ${remaining}, reset date: ${resetDate}")
    }
}
