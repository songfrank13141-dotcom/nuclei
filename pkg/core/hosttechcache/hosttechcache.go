package hosttechcache

import (
	"strings"
	"sync"

	"github.com/projectdiscovery/gologger"
)

// TechHint represents a detected technology on a host that can be used
// to filter templates before execution.
type TechHint struct {
	// DetectedTech is the technology detected on the host (e.g., "apache", "nginx", "iis").
	// Templates tagged with INCOMPATIBLE technologies will be skipped.
	DetectedTech string
}

// HostTechCache stores per-host technology hints derived from early HTTP
// responses (e.g. the Server: header). It is safe for concurrent use.
type HostTechCache struct {
	mu    sync.RWMutex
	hints map[string]*TechHint // keyed by normalised host (scheme+host)
}

// NewHostTechCache returns an initialised HostTechCache.
func NewHostTechCache() *HostTechCache {
	return &HostTechCache{hints: make(map[string]*TechHint)}
}

// RecordServerHeader inspects a raw Server header value and, if it contains
// a known technology keyword, records the detected tech for that host.
//
// Currently understood keywords:
//
//	"apache" → detected tech: "apache"
//	"nginx" → detected tech: "nginx"
//	"iis" or "microsoft-iis" → detected tech: "iis"
//	"tomcat" → detected tech: "tomcat"
//
// The mapping is intentionally simple and lowercase-compared so that
// "Apache/2.4.51 (Unix)" and "apache" both resolve to the same hint.
func (c *HostTechCache) RecordServerHeader(host, serverHeader string) {
	lower := strings.ToLower(serverHeader)

	var detectedTech string
	if strings.Contains(lower, "apache") {
		detectedTech = "apache"
	} else if strings.Contains(lower, "nginx") {
		detectedTech = "nginx"
	} else if strings.Contains(lower, "iis") || strings.Contains(lower, "microsoft-iis") {
		detectedTech = "iis"
	} else if strings.Contains(lower, "tomcat") {
		detectedTech = "tomcat"
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if detectedTech == "" {
		if _, exists := c.hints[host]; exists {
			gologger.Debug().Msgf("[tech-filter] CLEARED hint for host '%s' (unrecognised Server header: '%s')",
				host, serverHeader)
		}
		delete(c.hints, host)
		return
	}

	gologger.Debug().Msgf("[tech-filter] RECORDED hint for host '%s' — Server: '%s' → detected tech: %s",
		host, serverHeader, detectedTech)

	c.hints[host] = &TechHint{DetectedTech: detectedTech}
}

// ShouldSkipTemplate returns true when the cache has a hint for the given host
// AND the template is tagged for an INCOMPATIBLE technology.
//
// For example:
//   - If host has "apache" detected, skip templates tagged with "iis" or "nginx"
//   - If host has "iis" detected, skip templates tagged with "apache" or "nginx"
//
// Templates without tech-specific tags are NOT skipped (they are tech-agnostic).
// If there is no hint for the host the function always returns false (no skip).
func (c *HostTechCache) ShouldSkipTemplate(host string, templateTags []string) bool {
	c.mu.RLock()
	hint, ok := c.hints[host]
	c.mu.RUnlock()

	if !ok || hint.DetectedTech == "" {
		return false // no information → don't skip
	}

	// Define incompatible tech mappings
	incompatibleTech := map[string][]string{
		"apache":  {"iis", "nginx", "tomcat"},
		"nginx":   {"apache", "iis", "tomcat"},
		"iis":     {"apache", "nginx", "tomcat"},
		"tomcat":  {"apache", "nginx", "iis"},
	}

	badTags := incompatibleTech[hint.DetectedTech]
	if len(badTags) == 0 {
		return false // unknown tech → don't skip
	}

	// Check if template has any incompatible tech tags
	for _, tag := range templateTags {
		tagLower := strings.ToLower(tag)
		for _, badTag := range badTags {
			if tagLower == badTag {
				gologger.Debug().Msgf("[tech-filter] SKIPPED template with tag '%s' on '%s' host (detected: %s)",
					tag, hint.DetectedTech, host)
				return true // template has incompatible tech tag → skip
			}
		}
	}

	return false // no incompatible tags found → don't skip
}
