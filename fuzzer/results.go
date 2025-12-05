package fuzzer

import "time"

type Result struct {
    URL      string
    Payload  string
    Status   int
    Size     int
    Lines    int
    Words    int
    Duration time.Duration
    Body     string
    Headers  string
    Error    string
}