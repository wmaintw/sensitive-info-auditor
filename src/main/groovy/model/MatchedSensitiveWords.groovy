package model

class MatchedSensitiveWords {
    def ArrayList<String> generalSensitiveWords = []
    def ArrayList<String> clientSpecificSensitiveWords = []

    def isFound() {
        generalSensitiveWords.size() > 0 || clientSpecificSensitiveWords.size() > 0
    }
}
