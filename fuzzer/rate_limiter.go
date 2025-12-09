package fuzzer

import (
    "context"
    "fmt"
    "math/rand"
    "sync"
    "time"
)

/*
This package implements a flexible RateLimiter designed for fuzzer applications.
It uses the Token Bucket algorithm to control the request rate (RPS).

Key features include:
- Jitter support to randomize request timing.
- Adaptive mode, which automatically decreases the RPS when a high block rate (rate limit errors) is detected, and increases it when the success rate is high.
- Retry mechanism with different backoff strategies (linear, exponential, random).
*/

type RateLimiter struct {
    config        RateLimiterConfig
    tokens        chan struct{}
    stop          chan bool
    currentRPS    int
    mutex         sync.Mutex
    lastAdjustment time.Time
    blockedCount  int
    successCount  int
}

// NewRateLimiter creates a new RateLimiter instance.
func NewRateLimiter(config RateLimiterConfig) *RateLimiter {
    rps := config.RequestsPerSecond
    if rps <= 0 {
        rps = 100 // Default
    }
    
    rl := &RateLimiter{
        config:        config,
        tokens:        make(chan struct{}, rps),
        stop:          make(chan bool, 1),
        currentRPS:    rps,
        lastAdjustment: time.Now(),
    }
    
    // Fill initial bucket
    for i := 0; i < rps; i++ {
        rl.tokens <- struct{}{}
    }
    
    return rl
}

// Run starts the token refill mechanism and adaptive adjustment loop.
func (rl *RateLimiter) Run() {
    // Ticker for initial high-frequency token generation (deprecated pattern, but kept for context)
    // NOTE: In a standard token bucket, tokens are usually refilled in bulk or via the Wait() logic.
    ticker := time.NewTicker(time.Second / time.Duration(rl.currentRPS))
    defer ticker.Stop()
    
    // Ticker for periodic refill and adaptive adjustment
    refillTicker := time.NewTicker(time.Second)
    defer refillTicker.Stop()
    
    for {
        select {
        case <-ticker.C:
            // This case handles attempts to continuously add tokens based on currentRPS period.
            select {
                case rl.tokens <- struct{}{}:
                default:
            }
            
        case <-refillTicker.C:
            // Refill the bucket periodically
            rl.refillBucket()
            
            // Adaptive adjustment if enabled
            if rl.config.Adaptive {
                rl.adaptiveAdjustment()
            }
            
        case <-rl.stop:
            return
        }
    }
}

// Wait blocks until a token is available from the bucket.
func (rl *RateLimiter) Wait() {
    <-rl.tokens
    
    // Apply jitter if enabled
    if rl.config.Jitter {
        // Random delay up to 100ms
        jitter := time.Duration(rand.Intn(100)) * time.Millisecond
        time.Sleep(jitter)
    }
}

// refillBucket clears the current bucket and fills it with 'currentRPS' tokens.
func (rl *RateLimiter) refillBucket() {
    // Clear the channel capacity first (simplistic implementation of resetting the bucket)
    select {
        case <-rl.tokens:
        default:
    }
    
    // Fill bucket with new tokens up to the current limit
    rl.mutex.Lock()
    target := rl.currentRPS
    rl.mutex.Unlock()
    
    for i := 0; i < target; i++ {
        select {
        case rl.tokens <- struct{}{}:
        default:
            // Bucket is full
            break
        }
    }
}

// adaptiveAdjustment automatically adjusts the RPS based on blocked/success rates.
func (rl *RateLimiter) adaptiveAdjustment() {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    // Only adjust every 10 seconds
    if time.Since(rl.lastAdjustment) < 10*time.Second {
        return
    }
    
    total := rl.blockedCount + rl.successCount
    if total == 0 {
        return
    }
    
    blockRate := float64(rl.blockedCount) / float64(total)
    
    if blockRate > 0.3 { // More than 30% of blocked requests -> Decrease rate
        newRPS := rl.currentRPS / 2

        if newRPS < 1 {
            newRPS = 1
        }

        rl.currentRPS = newRPS
        fmt.Printf("[rate-limiter] :: Rate reduced to %d RPS (block rate: %.1f%%)\n", 
            newRPS, blockRate*100)
    } else if blockRate < 0.05 && rl.currentRPS < rl.config.RequestsPerSecond { // Less than 5% blocked and below configured max -> Increase rate
        newRPS := rl.currentRPS * 2

        if newRPS > rl.config.RequestsPerSecond {
            newRPS = rl.config.RequestsPerSecond
        }

        rl.currentRPS = newRPS
        fmt.Printf("[rate-limiter] :: Rate increased to %d RPS (block rate: %.1f%%)\n", 
            newRPS, blockRate*100)
    }
    
    // Reset counters
    rl.blockedCount = 0
    rl.successCount = 0
    rl.lastAdjustment = time.Now()
}

// RecordBlocked increments the counter for rate-limited/blocked requests.
func (rl *RateLimiter) RecordBlocked() {
    rl.mutex.Lock()
    rl.blockedCount++
    rl.mutex.Unlock()
}

// RecordSuccess increments the counter for successful requests.
func (rl *RateLimiter) RecordSuccess() {
    rl.mutex.Lock()
    rl.successCount++
    rl.mutex.Unlock()
}

// AdjustRate manually changes the current RPS limit.
func (rl *RateLimiter) AdjustRate(delta int) {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    newRPS := rl.currentRPS + delta
    if newRPS < 1 {
        newRPS = 1
    }
    if newRPS > 1000 { // Arbitrary maximum to prevent overflow
        newRPS = 1000
    }
    
    rl.currentRPS = newRPS
    fmt.Printf("[rate-limiter] :: Rate adjusted to %d RPS\n", newRPS)
}

// Stop signals the Run loop to exit gracefully.
func (rl *RateLimiter) Stop() {
    select {
    case rl.stop <- true:
    default:
    }
}

// RetryWithBackoff executes a function with retries and a delay (backoff) between attempts.
func (rl *RateLimiter) RetryWithBackoff(ctx context.Context, fn func() error) error {
    for attempt := 1; attempt <= rl.config.MaxRetries; attempt++ {
        err := fn()
        if err == nil {
            return nil
        }
        
        // Calculate the delay based on the attempt number
        delay := rl.calculateBackoff(attempt)
        
        select {
        case <-time.After(delay):
            // Wait completed, continue to the next attempt
            continue
        case <-ctx.Done():
            // Context cancelled, stop retrying
            return ctx.Err()
        }
    }
    
    return fmt.Errorf("max retries exceeded")
}

// calculateBackoff determines the delay duration based on the configured strategy.
func (rl *RateLimiter) calculateBackoff(attempt int) time.Duration {
    baseDelay := time.Second
    
    switch rl.config.BackoffStrategy {
    case "linear":
        return baseDelay * time.Duration(attempt)
    case "exponential":
        delay := baseDelay
        // Calculate delay * 2^(attempt-1)
        for i := 1; i < attempt; i++ {
            delay *= 2
        }
        return delay
    case "random":
        // Random delay up to baseDelay * 2 * attempt
        maxDelay := baseDelay * time.Duration(attempt*2)
        return time.Duration(rand.Int63n(int64(maxDelay)))
    default:
        // Default to a fixed base delay
        return baseDelay
    }
}