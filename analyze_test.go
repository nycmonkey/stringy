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

var mssqlAnalyzeTests = []testpair{
	{"Jonathan", []string{"jonathan"}},
	{"Jonathan Summer", []string{"jonathan", "summer"}},
	{"žůžo", []string{"žůžo"}},
	{"Société Générale", []string{"société", "générale"}},
	{"I don't care!  You are stUpid...", []string{"i", "don't", "care", "you", "are", "stupid"}},
	{"amazon.com", []string{"amazon", "com"}},
	{"amazon.com, inc.", []string{"amazon", "com", "inc"}},
	{"J.C. Penney", []string{"jc", "penney"}},
	{"J. C. Penney", []string{"j", "c", "penney"}},
	{"Heath/Bar foo.bar", []string{"heath", "bar", "foo", "bar"}},
	{"H.R.M. The Queen", []string{"hrm", "the", "queen"}},
	{"", []string{}},
}

func TestMSAnalyze(t *testing.T) {
	for _, pair := range mssqlAnalyzeTests {
		got := MSAnalyze(pair.input)
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

var shingleTests = []ngramTestPair{
	{[]string{"jonathan"}, []string{"jonathan"}},
	{[]string{"jonathan", "summer"}, []string{"jonathan", "jonathan_summer", "summer"}},
	{[]string{"c", "b", "a"}, []string{"a", "b", "b_a", "c", "c_b", "c_b_a"}},
	{[]string{}, []string{}},
}

func TestShingles(t *testing.T) {
	for _, pair := range shingleTests {
		got := Shingles(pair.input)
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

var paddedCharacterTrigramTests = []testpair{
	{"dog", []string{"$do", "dog", "og$"}},
	{"dogs", []string{"$do", "dog", "ogs", "gs$"}},
	{"do", []string{"$do", "do$"}},
	{"", nil},
	{"d", []string{"$d$"}},
	{"the_band", []string{"$th", "the", "he_", "e_b", "_ba", "ban", "and", "nd$"}},
	{"lucky 7", []string{"$lu", "luc", "uck", "cky", "ky ", "y 7", " 7$"}},
	{"T", []string{"$T$"}},
	{"AAPL", []string{"$AA", "AAP", "APL", "PL$"}},
}

func TestPaddedCharacterTrigrams(t *testing.T) {
	for _, pair := range paddedCharacterTrigramTests {
		got := PaddedCharacterTrigrams(pair.input)
		if !reflect.DeepEqual(got, pair.output) {
			t.Error(
				"For", pair.input,
				"expected", pair.output,
				"got", got,
			)
		}
	}
}

var characterTrigramTests = []testpair{
	{"dog", []string{"dog"}},
	{"dogs", []string{"dog", "ogs"}},
	{"do", []string{"do"}},
	{"", nil},
	{"d", []string{"d"}},
	{"the_band", []string{"the", "he_", "e_b", "_ba", "ban", "and"}},
	{"lucky 7", []string{"luc", "uck", "cky", "ky ", "y 7"}},
	{"T", []string{"T"}},
	{"AAPL", []string{"AAP", "APL"}},
}

func TestCharacterTrigrams(t *testing.T) {
	for _, pair := range characterTrigramTests {
		got := CharacterTrigrams(pair.input)
		if !reflect.DeepEqual(got, pair.output) {
			t.Error(
				"For", pair.input,
				"expected", pair.output,
				"got", got,
			)
		}
	}
}

var bigramTests = []ngramTestPair{
	{[]string{""}, []string{""}},
	{[]string{"jonathan"}, []string{"jonathan"}},
	{[]string{"jonathan", "summer"}, []string{"jonathan_summer"}},
	{[]string{"jonathan", "ari", "summer"}, []string{"ari_summer", "jonathan_ari"}},
	{[]string{"a", "b", "c", "d"}, []string{"a_b", "b_c", "c_d"}},
	{[]string{}, []string{}},
}

func TestBigrams(t *testing.T) {
	for _, pair := range bigramTests {
		got := Bigrams(pair.input)
		if len(got) != len(pair.output) {
			t.Error(
				"For", pair.input,
				"expected", pair.output,
				"got", got,
			)
		}
		for i, want := range pair.output {
			if len(got) <= i {
				t.Fatal(
					"For", pair.input,
					"expected", pair.output,
					"got", got,
				)
			}
			if got[i] != want {
				t.Error(
					"For", pair.input,
					"expected", pair.output,
					"got", got,
				)
			}
		}
	}
}
