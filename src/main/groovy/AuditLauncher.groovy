import audit.Auditor
import groovy.time.TimeCategory
import groovy.util.logging.Slf4j

import static utils.CommandLineLogger.log

@Slf4j
class AuditLauncher {

    static def main(args) {
        def auditor = new Auditor()

        def startDate = logScanStartDate()
        auditor.doAudit()
        logScanEndDate(startDate)
    }

    def static logScanStartDate() {
        def startDate = new Date()
        log("Start auditing, ${startDate}")
        startDate
    }

    def static void logScanEndDate(startDate) {
        def finishDate = new Date()
        use(TimeCategory) {
            def duration = finishDate - startDate
            log("Done, duration: ${duration}")
        }
    }
}
