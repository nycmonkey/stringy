package stringy

import (
	"reflect"
	"testing"
)

type testpair struct {
	input  string
	output []string
}

type ngramTestPair struct {
	input  []string
	output []string
}

var analyzeTests = []testpair{
	{"Jonathan", []string{"jonathan"}},
	{"Jonathan Summer", []string{"jonathan", "summer"}},
	{"žůžo", []string{"zuzo"}},
	{"Société Générale", []string{"societe", "generale"}},
	{"I don't care!  You are stUpid...", []string{"i", "dont", "care", "you", "are", "stupid"}},
	{"pOOpsicLe", []string{"poopsicle"}},
	{"2Legit2Quit!", []string{"2legit2quit"}},
	{"über Spaß", []string{"uber", "spass"}},
	{"16 Handles", []string{"16", "handles"}},
	{"", []string{}},
}

func TestAnalyze(t *testing.T) {
	for _, pair := range analyzeTests {
		got := Analyze(pair.input)
		if !reflect.DeepEqual(got, pair.output) {
			t.Error(
				"For", pair.input,
				"expected", pair.output,
				"got", got,
			)
		}
	}
}

var ngramTests = []ngramTestPair{
	{[]string{"jonathan"}, []string{"jonathan"}},
	{[]string{"jonathan", "summer"}, []string{"jonathan", "jonathan_summer", "summer"}},
	{[]string{"societe", "generale"}, []string{"generale", "societe", "societe_generale"}},
	{[]string{"16", "handles"}, []string{"16_handles", "handles"}},
	{[]string{}, []string{}},
}

func TestUnigramsAndBigrams(t *testing.T) {
	for _, pair := range ngramTests {
		got := UnigramsAndBigrams(pair.input)
		if !reflect.DeepEqual(got, pair.output) {
			t.Error(
				"For", pair.input,
				"expected", pair.output,
				"got", got,
			)
		}
	}
}

var urlAnalyzeTests = []testpair{
	{"www.veritypartners.com", []string{"veritypartners.com"}},
	{"http://www.veritypartners.com", []string{"veritypartners.com"}},
	{"http://www.veritypartners.com/foo/bar.html", []string{"veritypartners.com"}},
	{"http://www.veritypartners.com/foo/bar.html?q=%20foo%", []string{"veritypartners.com"}},
	{"http://www.veritypartners.com:2000/foo/bar.html?q=%20foo%", []string{"veritypartners.com"}},
}

func TestURLAnalyze(t *testing.T) {
	for _, pair := range urlAnalyzeTests {
		got := URLAnalyze(pair.input)
		if !reflect.DeepEqual(got, pair.output) {
			t.Error(
				"For", pair.input,
				"expected", pair.output,
				"got", got,
			)
		}
	}
}
