package utils

class CommandLineLogger {
    def static log(GString logMessage) {
        println "${new Date()} ${logMessage}"
    }
}
