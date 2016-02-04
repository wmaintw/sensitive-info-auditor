package audit

class SensitiveInfoReporter {
    private static final String WORDS_SEPERATOR = ' | '
    private static final String REPORT_HEADER = "Account, Repo, Possible sensitive info found, " +
            "Places where the possible sensitive info was found, " +
            "Filename or Commit message, Commit html url, Commit SHA \n"

    def reportDate = new Date()

    def storeFindings(record) {
        File reportFilePath = createReportFolder()
        def reportFileForEachUser = new File(reportFilePath, "${record.user}.csv")
        buildHeaderLine(reportFileForEachUser)
        appendToReportFile(reportFileForEachUser, record)
    }

    synchronized createReportFolder() {
        def reportFilePath = new File("scan-report/${reportDate.time}")
        if (!reportFilePath.exists()) {
            reportFilePath.mkdirs()
        }
        reportFilePath
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
        "${record.user}, ${record.repo}, ${record.matchedSensitiveWords.join(WORDS_SEPERATOR)}, " +
                "${record.whereTheSensitiveWordsFound}, ${record.filename}, " +
                "${record.commitHtmlUrl}, ${record.commitSha}"
    }
}
