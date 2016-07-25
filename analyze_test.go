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
	{"", []string{}},
}

var ngramTests = []ngramTestPair{
	{[]string{"jonathan"}, []string{"jonathan"}},
	{[]string{"jonathan", "summer"}, []string{"jonathan", "jonathan_summer", "summer"}},
	{[]string{"societe", "generale"}, []string{"generale", "societe", "societe_generale"}},
	{[]string{}, []string{}},
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
