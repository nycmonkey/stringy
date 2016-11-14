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
	abbreviation  = regexp.MustCompile(`\b(?:[a-zA-Z]\.){2,}`)
	punctuation   = regexp.MustCompile(`[\p{P}\p{S}]`)
	possessives   = regexp.MustCompile(`([a-zA-Z]+['’][a-zA-Z]+)`)
	apostrophes   = regexp.MustCompile(`['’]`)
	onlyNumbers   = regexp.MustCompile(`^[0-9,.]+$`)
	domainPattern = regexp.MustCompile(`(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])+`)
	padding       = []rune{'$'}
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

// MSAnalyze normalizes and tokenizes a given input stream according to rules reverse engineered to match
// what MS SQL Server full text indexer does
func MSAnalyze(in string) (tokens []string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintln(os.Stderr, "RECOVERED FROM", r)
			fmt.Fprintln(os.Stderr, "Offending input:", in)
		}
	}()
	for _, abbr := range abbreviation.FindAllString(in, -1) {
		abbrSansPeriods := punctuation.ReplaceAllString(abbr, "")
		in = strings.Replace(in, abbr, abbrSansPeriods, -1)
	}
	for _, quotation := range possessives.FindAllString(in, -1) {
		tempSub := apostrophes.ReplaceAllString(quotation, "qlqlql")
		in = strings.Replace(in, quotation, tempSub, -1)
	}
	in = punctuation.ReplaceAllString(in, " ")
	in = strings.Replace(in, "qlqlql", "'", -1)
	tokens = make([]string, 0)
	for _, t := range strings.Fields(in) {
		tokens = append(tokens, strings.ToLower(t))
	}
	return
}

// Shingles returns a sorted array of shingle combinations for the given input
func Shingles(tokens []string) (result []string) {
	if len(tokens) == 0 {
		return []string{}
	}
	if len(tokens) == 1 {
		return tokens
	}
	for shingleLen := 1; shingleLen <= len(tokens); shingleLen++ {
		for startIdx := 0; startIdx <= len(tokens)-shingleLen; startIdx++ {
			result = append(result, strings.Join(tokens[startIdx:startIdx+shingleLen], "_"))
		}
	}
	sort.Strings(result)
	return
}

// PaddedCharacterTrigrams returns a slice of character trigrams padded with '$'
func PaddedCharacterTrigrams(token string) (result []string) {
	if len(token) == 0 {
		return
	}
	padded := append(padding, append([]rune(token), padding...)...)
	for i := 0; i < len(padded)-2; i++ {
		result = append(result, string(padded[i:i+3]))
	}
	return
}

// CharacterTrigrams returns a slice of character trigrams without padding
func CharacterTrigrams(token string) (result []string) {
	if len(token) == 0 {
		return
	}
	if len(token) < 4 {
		return []string{token}
	}
	for i := 0; i < len(token)-2; i++ {
		result = append(result, token[i:i+3])
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

// URLAnalyze attempts to normalize a URL to a simple host name
// or returns an empty slice
func URLAnalyze(in string) (tokens []string) {
	tokens = make([]string, 0)
	raw := strings.ToLower(strings.TrimSpace(in))
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

// Bigrams returns the unique token bigrams for a given ordered list of string tokens
func Bigrams(tokens []string) (bigrams sort.StringSlice) {
	switch len(tokens) {
	case 0:
		return
	case 1:
		return tokens
	case 2:
		return []string{tokens[0] + "_" + tokens[1]}
	}
	for i := 0; i < len(tokens)-1; i++ {
		token := tokens[i] + "_" + tokens[i+1]
		l := len(bigrams)
		if l == 0 {
			bigrams = append(bigrams, token)
			continue
		}
		idx := bigrams.Search(token)
		if idx < l && bigrams[idx] == token {
			// already present
			continue
		}
		if idx == l {
			bigrams = append(bigrams, token)
			continue
		}
		bigrams = append(bigrams, "")
		copy(bigrams[idx+1:], bigrams[idx:])
		bigrams[idx] = token
	}
	return
}
