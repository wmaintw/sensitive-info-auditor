package utils

class CommandLineLogger {
    def static log(String logMessage) {
        println "${new Date()} ${logMessage}"
    }
}
