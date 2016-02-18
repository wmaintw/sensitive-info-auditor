package audit

import model.Findings

class SensitiveInfoReporter {
    private static final String WORDS_SEPERATOR = ' | '
    private static final String REPORT_HEADER = "Account, Repo, Possible client sensitive info found, " +
            "Possible general sensitive info found, " +
            "Places where the possible sensitive info was found, " +
            "Filename or Commit message, Commit html url, Commit SHA \n"
    private static final String DEFAULT_REPORT_FOLDER = "scan-report"

    private SummaryReporter summaryReporter = new SummaryReporter()

    def storeFindings(Findings record) {
        summaryReporter.register(record)
        store(record)
    }

    def void store(Findings record) {
        File reportFilePath = createReportFolder()
        def reportFileForEachUser = new File(reportFilePath, "${record.user}.csv")
        buildHeaderLine(reportFileForEachUser)
        appendToReportFile(reportFileForEachUser, record)
    }

    synchronized createReportFolder() {
        def reportFilePath = new File(reportFolderName())
        if (!reportFilePath.exists()) {
            reportFilePath.mkdirs()
        }
        reportFilePath
    }

    private String reportFolderName() {
        DEFAULT_REPORT_FOLDER
    }

    def void buildHeaderLine(File reportFile) {
        if (!reportFile.exists()) {
            reportFile << REPORT_HEADER
        }
    }

    def File appendToReportFile(File reportFile, Findings record) {
        reportFile << "${formatFindings(record)} \n"
    }

    def formatFindings(Findings record) {
        "${record.user}, ${record.repoName}, ${record.matchedSensitiveWords.clientSpecificSensitiveWords.join(WORDS_SEPERATOR)}, " +
                "${record.matchedSensitiveWords.generalSensitiveWords.join(WORDS_SEPERATOR)}, " +
                "${record.whereTheSensitiveWordsFound}, ${record.filename}, " +
                "${record.commitHtmlUrl}, ${record.commitSha}"
    }

    def generateSummaryReport() {
        summaryReporter.generateSummaryReport(reportFolderName())
    }
}
