package email

import "time"

// Graph internals exposed for tests, without waiting on the real clock.

const (
	GraphMaxRequest  = graphMaxRequest
	GraphLightBytes  = graphLightBytes
	GraphHeavyVolume = graphHeavyVolume
	GraphSlots       = graphSlots
	GraphHeavySlots  = graphHeavySlots
)

func (g *Graph) ExpireToken() {
	g.mu.Lock()
	g.tokenUntil = time.Time{}
	g.mu.Unlock()
}

func (g *Graph) ForgetTokenRefusal() {
	g.mu.Lock()
	g.tokenErrUntil = time.Time{}
	g.mu.Unlock()
}

func (g *Graph) ThrottledFor() time.Duration { return g.throttled() }

func (g *Graph) EndThrottle() {
	g.mu.Lock()
	g.throttledUntil = time.Time{}
	g.mu.Unlock()
}

func (g *Graph) Spend(n int) bool { return g.spend(n) }

func (g *Graph) EndWindow() {
	g.mu.Lock()
	g.windowStart = time.Time{}
	g.mu.Unlock()
}
