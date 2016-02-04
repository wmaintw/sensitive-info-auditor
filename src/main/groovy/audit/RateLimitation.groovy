package audit

class RateLimitation {
    def remaining
    def resetDate

    RateLimitation(int remaining, Date resetDate) {
        this.remaining = remaining
        this.resetDate = resetDate
    }
}
