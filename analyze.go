package stringy

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/fiam/gounidecode/unidecode"

	"golang.org/x/text/transform"
	"golang.org/x/text/unicode/norm"
)

var (
	punctuation = regexp.MustCompile(`[\p{P}\p{S}]`)
	onlyNumbers = regexp.MustCompile(`^[0-9,.]+$`)
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
	var normalization = transform.Chain(norm.NFD, transform.RemoveFunc(isMn), norm.NFC)
	tokens = make([]string, 0)
	for _, t := range strings.Fields(in) {
		t2 := punctuation.ReplaceAllString(t, "")
		if len(t2) < 1 {
			continue
		}
		t3, _, _ := transform.String(normalization, t2)
		if len(t3) > 0 {
			tokens = append(tokens, strings.ToLower(unidecode.Unidecode(t3)))
		}
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
