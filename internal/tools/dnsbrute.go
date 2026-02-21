package tools

import (
	_ "embed"
	"context"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/SMBullet/Survex/internal/models"
)

//go:embed wordlist.txt
var wordlistData string

// bruteWordlist is the deduplicated list of subdomain prefixes loaded from wordlist.txt.
var bruteWordlist []string

func init() {
	seen := make(map[string]struct{})
	for _, line := range strings.Split(wordlistData, "\n") {
		word := strings.TrimSpace(line)
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if _, dup := seen[word]; !dup {
			seen[word] = struct{}{}
			bruteWordlist = append(bruteWordlist, word)
		}
	}
}

// permutationSuffixes are environment/variant suffixes appended to discovered subdomains.
var permutationSuffixes = []string{
	"-dev", "-staging", "-stage", "-stg", "-test", "-qa", "-uat",
	"-prod", "-production", "-preprod", "-preview", "-sandbox", "-demo",
	"-new", "-old", "-v2", "-v1", "-api", "-admin", "-internal",
	"2", "1", "-2", "-1",
}

// permutationPrefixes are environment/variant prefixes prepended to discovered subdomains.
var permutationPrefixes = []string{
	"dev-", "staging-", "test-", "qa-", "uat-", "prod-", "preprod-",
	"new-", "old-", "v2-", "v1-", "api-", "admin-", "internal-",
}

// RunDNSBrute performs DNS brute-force enumeration for the given domain.
// It concurrently resolves prefix.domain for each word in the embedded wordlist.
// Returns the set of confirmed live subdomains (those that resolve to at least one IP).
func RunDNSBrute(domain string, timeoutSecs int) []string {
	if timeoutSecs <= 0 {
		timeoutSecs = 5
	}

	candidates := make([]string, 0, len(bruteWordlist))
	for _, word := range bruteWordlist {
		candidates = append(candidates, word+"."+domain)
	}

	return resolveMany(candidates, timeoutSecs)
}

// Permutate takes already-discovered subdomains and generates plausible variants.
// For example, "api.example.com" → "api-v2.example.com", "api-staging.example.com", etc.
// Returns confirmed live permutations that resolve to an IP.
func Permutate(subdomains []models.Subdomain, domain string, timeoutSecs int) []string {
	if timeoutSecs <= 0 {
		timeoutSecs = 5
	}

	seen := make(map[string]struct{})
	var candidates []string

	for _, sub := range subdomains {
		name := sub.Name
		// Strip the root domain to get the subdomain prefix
		prefix := strings.TrimSuffix(name, "."+domain)
		if prefix == name || prefix == "" || prefix == domain {
			continue
		}

		for _, suf := range permutationSuffixes {
			candidate := prefix + suf + "." + domain
			if _, dup := seen[candidate]; !dup {
				seen[candidate] = struct{}{}
				candidates = append(candidates, candidate)
			}
		}

		for _, pre := range permutationPrefixes {
			candidate := pre + prefix + "." + domain
			if _, dup := seen[candidate]; !dup {
				seen[candidate] = struct{}{}
				candidates = append(candidates, candidate)
			}
		}
	}

	return resolveMany(candidates, timeoutSecs)
}

// resolveMany concurrently resolves a list of hostnames and returns those that
// have at least one A/AAAA record. Uses a semaphore of 50 concurrent goroutines.
func resolveMany(candidates []string, timeoutSecs int) []string {
	if len(candidates) == 0 {
		return nil
	}

	var (
		mu      sync.Mutex
		results []string
		wg      sync.WaitGroup
		sem     = make(chan struct{}, 50)
	)

	r := &net.Resolver{PreferGo: true}

	for _, host := range candidates {
		wg.Add(1)
		go func(h string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
			defer cancel()

			addrs, err := r.LookupHost(ctx, h)
			if err == nil && len(addrs) > 0 {
				mu.Lock()
				results = append(results, h)
				mu.Unlock()
			}
		}(host)
	}

	wg.Wait()
	return results
}
