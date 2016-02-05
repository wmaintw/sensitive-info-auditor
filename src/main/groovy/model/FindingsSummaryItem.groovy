package model

class FindingsSummaryItem {
    def String sensitiveWord
    def int counter = 0
    def ArrayList<String> githubAccountList = []

    FindingsSummaryItem(String sensitiveWord, int counter) {
        this.sensitiveWord = sensitiveWord
        this.counter = counter
    }
}
