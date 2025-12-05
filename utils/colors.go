package utils

import (
    "fmt"
    "github.com/fatih/color"
    "time"
)

var (
    Green   = color.New(color.FgGreen)
    Red     = color.New(color.FgRed)
    Yellow  = color.New(color.FgYellow)
    Blue    = color.New(color.FgBlue)
    Cyan    = color.New(color.FgCyan)
    Magenta = color.New(color.FgMagenta)
    White   = color.New(color.FgWhite)
)

func InitColors(enabled bool) {
    color.NoColor = !enabled
}

func FormatDuration(seconds float64) string {
    dur := time.Duration(seconds * float64(time.Second))
    
    if dur < time.Minute {
        return fmt.Sprintf("%.0fs", dur.Seconds())
    } else if dur < time.Hour {
        minutes := int(dur.Minutes())
        seconds := int(dur.Seconds()) % 60
        return fmt.Sprintf("%dm%ds", minutes, seconds)
    } else {
        hours := int(dur.Hours())
        minutes := int(dur.Minutes()) % 60
        return fmt.Sprintf("%dh%dm", hours, minutes)
    }
}