package audit

import model.Findings
import model.FindingsSummary
import model.FindingsSummaryItem

class SummaryReporter {
    private Map<String, ArrayList<Findings>> generalRegistry = new HashMap<>()
    private Map<String, ArrayList<Findings>> clientRegistry = new HashMap<>()
    private Set<String> suspectGithubAccounts = new HashSet<>()

    def void register(Findings record) {
        registerSensitiveWord(generalRegistry, record.matchedSensitiveWords.generalSensitiveWords, record)
        registerSensitiveWord(clientRegistry, record.matchedSensitiveWords.clientSpecificSensitiveWords, record)
    }

    private void registerSensitiveWord(HashMap<String, ArrayList<Findings>> registry, ArrayList<String> words, Findings record) {
        for (String word : words) {
            if (!isRegistered(registry, word)) {
                registry.put(word, [record])
            } else {
                registry.get(word).add(record)
            }
        }

        suspectGithubAccounts.add(record.user)
    }

    private isRegistered(HashMap<String, ArrayList<Findings>> registry, String word) {
        registry.containsKey(word)
    }

    def generateSummaryReport(String reportFolderName) {
        def summary = translateToSummary()

        def reportFile = createSummaryReportFile(reportFolderName)
        storeToSummaryFile(summary, reportFile)
    }

    private FindingsSummary translateToSummary() {
        def summary = new FindingsSummary()
        summary.amountOfSuspectGithubAccountInTotal = suspectGithubAccounts.size()
        transformToClientSpecificSummary(summary)
        transformToGeneralSummary(summary)

        summary
    }

    private void transformToClientSpecificSummary(FindingsSummary summary) {
        for (Map.Entry<String, ArrayList<Findings>> entry : clientRegistry.entrySet()) {
            def item = new FindingsSummaryItem(entry.key, entry.value.size())
            item.githubAccountList = entry.value.collect() { it.user }

            summary.clientSpecificSensitiveWordsSummary.add(item)
        }
    }

    private void transformToGeneralSummary(FindingsSummary summary) {
        for (Map.Entry<String, ArrayList<Findings>> entry : generalRegistry.entrySet()) {
            def item = new FindingsSummaryItem(entry.key, entry.value.size())
            item.githubAccountList = entry.value.collect() { it.user }

            summary.generalSensitiveWordsSummary.add(item)
        }
    }

    private createSummaryReportFile(String reportFolderName) {
        File summaryReportFilePath = createReportFolder(reportFolderName)
        new File(summaryReportFilePath, "summary-scan-report.html")
    }

    private createReportFolder(String reportFolderName) {
        def reportFilePath = new File("scan-report/${reportFolderName}")
        if (!reportFilePath.exists()) {
            reportFilePath.mkdirs()
        }
        reportFilePath
    }

    private void storeToSummaryFile(FindingsSummary summary, File reportFile) {
        reportFile << formatToHtml(summary)
    }

    private String formatToHtml(FindingsSummary summary) {
        "<!DOCTYPE html><html><head><title>Github Sensitive Info Scan Summary Report</title>" +
                "<style>table, th, td {border: 1px solid grey;border-collapse: collapse;}th, td {padding: 5px;text-align: left;} .githubAccounts {display: none}</style>" +
                "<script src=\"//code.jquery.com/jquery-1.12.0.min.js\"></script>" +
                "<script src=\"//code.jquery.com/jquery-migrate-1.2.1.min.js\"></script>" +
                "</head><body>" +
                "<h1>Github Sensitive Info Scan Summary Report</h1>" +
                "<div>found sensitive info in <b>${suspectGithubAccounts.size()}</b> github account</div>" +
                "<div>scan finished at: ${reportGeneratedDateTime()}</div>" +
                "<br />" +
                "<h2>Client Specific Sensitive Words Found (${summary.clientSpecificSensitiveWordsSummary.size()} in total):</h2>" +
                "<table><tr><th>Sensitive Words</th><th>Found n Times</th><th>Github Accounts, <a href=\"#\" onClick=\"\$('.githubAccounts').toggle()\">show / hide all</a></th></tr>" +
                "${formatToHtmlTableRows(summary.clientSpecificSensitiveWordsSummary)}</table>" +
                "<h2>General Sensitive Words Found (${summary.generalSensitiveWordsSummary.size()} in total):</h2>" +
                "<table><tr><th>Sensitive Words</th><th>Found n Times</th><th>Github Accounts, <a href=\"#\" onClick=\"\$('.githubAccounts').toggle()\">show / hide all</a></th></tr>" +
                "${formatToHtmlTableRows(summary.generalSensitiveWordsSummary)}</table>" +
                "</body></html>"
    }

    private String formatToHtmlTableRows(ArrayList<FindingsSummaryItem> summaryItems) {
        def htmlTableRows = []

        summaryItems = summaryItems.sort { left, right -> right.counter <=> left.counter }

        for (FindingsSummaryItem item : summaryItems) {
            def githubAccounts = uniqueGithubAccounts(item.githubAccountList)
            htmlTableRows.add("<tr><td>${item.sensitiveWord}</td>" +
                    "<td>${item.counter}</td>" +
                    "<td>${githubAccounts.size()} in total" +
                        "<span class='githubAccounts'>, ${githubAccounts}</span></td></tr>")
        }

        htmlTableRows.join(" ")
    }

    private List<String> uniqueGithubAccounts(ArrayList<String> accounts) {
        accounts.unique { left, right -> left <=> right }
    }

    private String reportGeneratedDateTime() {
        new Date().format("yyyy-MM-dd hh:mm:ss")
    }
}
