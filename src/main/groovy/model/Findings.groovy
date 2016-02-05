package model

import utils.WhereSensitiveWordsFound

class Findings {
    def user
    def repoName
    def commitSha
    def MatchedSensitiveWords matchedSensitiveWords
    def WhereSensitiveWordsFound whereTheSensitiveWordsFound
    def filename
    def fileBlobUrl
    def commitHtmlUrl
}
