package stringy

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/fiam/gounidecode/unidecode"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

var (
	punctuation   = regexp.MustCompile(`[\p{P}\p{S}]`)
	onlyNumbers   = regexp.MustCompile(`^[0-9,.]+$`)
	domainPattern = regexp.MustCompile(`(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])+`)
)

func isMn(r rune) bool {
	return unicode.Is(unicode.Mn, r) // Mn: nonspacing marks
}

// Analyze normalizes and tokenizes a given input stream
func Analyze(in string) (tokens []string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "RECOVERED FROM", r)
			fmt.Fprintln(os.Stderr, "Offending input:", in)
		}
	}()
	tokens = make([]string, 0)
	for _, t := range strings.Fields(in) {
		t2 := punctuation.ReplaceAllString(t, "")
		if len(t2) < 1 {
			continue
		}
		if len(t2) == utf8.RuneCountInString(t2) {
			tokens = append(tokens, strings.ToLower(t2))
			continue
		}
		var normalization = transform.Chain(norm.NFD, transform.RemoveFunc(isMn), norm.NFC)
		t3, _, _ := transform.String(normalization, t2)
		tokens = append(tokens, strings.ToLower(unidecode.Unidecode(t3)))
	}
	return
}

func hostByRegex(in string) []string {
	m := domainPattern.FindAllString(in, 1)
	if len(m) == 0 {
		return []string{}
	}
	host := trimWWWPrefix(m[0])
	if !strings.Contains(host, ".") {
		return []string{}
	}
	return []string{host}
}

func trimWWWPrefix(in string) string {
	return strings.TrimPrefix(in, "www.")
}

func URLAnalyze(in string) (tokens []string) {
	tokens = make([]string, 0)
	raw := strings.TrimSpace(in)
	if len(raw) < 1 {
		return
	}
	u, err := url.Parse(raw)
	if err != nil || len(u.Host) < 1 {
		// fallback to regex
		return hostByRegex(raw)
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		h := strings.TrimPrefix(u.Host, "www.")
		if len(h) > 0 {
			tokens = append(tokens, h)
			return
		}
		return
	}
	h := strings.TrimPrefix(host, "www.")
	if len(h) > 0 {
		tokens = append(tokens, h)
		return
	}
	return
}

// UnigramsAndBigrams returns the unique token unigrams and bigrams for a given ordered list of string tokens
func UnigramsAndBigrams(tokens []string) (ngrams []string) {
	set := make(map[string]bool)
	for _, t := range tokens {
		if onlyNumbers.MatchString(t) {
			continue
		}
		set[t] = true
	}
	for i := 1; i < len(tokens); i++ {
		set[tokens[i-1]+"_"+tokens[i]] = true
	}
	ngrams = make([]string, len(set))
	i := 0
	for k := range set {
		ngrams[i] = k
		i++
	}
	sort.Strings(ngrams)
	return
}
