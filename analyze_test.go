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

type bytesTestPair struct {
	input  []byte
	output [][]byte
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

var analyzeBytesTests = []bytesTestPair{
	{[]byte("Jonathan"), [][]byte{[]byte("jonathan")}},
	{[]byte("Jonathan Summer"), [][]byte{[]byte("jonathan"), []byte("summer")}},
	{[]byte("žůžo"), [][]byte{[]byte("zuzo")}},
	{[]byte("Société Générale"), [][]byte{[]byte("societe"), []byte("generale")}},
	{[]byte("über Spaß"), [][]byte{[]byte("uber"), []byte("spass")}},
}

func TestAnalyzeBytes(t *testing.T) {
	for _, pair := range analyzeBytesTests {
		got := AnalyzeBytes(pair.input)
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

type nGramTest struct {
	s   string
	ln  int
	out []string
}

var tokenNGramTests = []nGramTest{
	{"a", 2, []string{"$a"}},
	{"a", 3, []string{"$$a"}},
	{"ab", 2, []string{"$a", "ab"}},
	{"ab", 3, []string{"$$a", "$ab"}},
	{"abc", 2, []string{"$a", "ab", "bc"}},
	{"abc", 3, []string{"$$a", "$ab", "abc"}},
	{"abcd", 2, []string{"$a", "ab", "bc", "cd"}},
	{"abcd", 3, []string{"$$a", "$ab", "abc", "bcd"}},
	{"", 2, nil},
	{"", 3, nil},
	{" ", 3, []string{"$$ "}},
	{"abcd", -1, nil},
	{"abcd", 0, nil},
	{"abcd", 1, []string{"a", "b", "c", "d"}},
}

func TestTokenNGrams(t *testing.T) {
	for _, tst := range tokenNGramTests {
		got := TokenNGrams(tst.s, tst.ln)
		if !reflect.DeepEqual(got, tst.out) {
			t.Error(
				"For", tst.s, tst.ln,
				"expected", tst.out,
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

type nGramSimilarityTest struct {
	s1, s2     string
	nGramLen   int
	similarity float64
}

var NGramSimilarityTests = []nGramSimilarityTest{
	{"", "", 2, 1.0},
	{"", "a", 2, 0},
	{"foo", "foo", 2, 1.0},
	{"foo", "arg", 2, 0.0},
}

func TestNGramSimilarity(t *testing.T) {
	for _, tst := range NGramSimilarityTests {
		got := NGramSimilarity(tst.s1, tst.s2, tst.nGramLen)
		if got != tst.similarity {
			t.Error(
				"For", tst.s1, tst.s2, tst.nGramLen,
				"expected", tst.similarity,
				"got", got,
			)
		}
	}
}

func benchmarkAnalyze(s string, b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		Analyze(s)
	}
}

func BenchmarkAnalyzeDiacritic(b *testing.B) { benchmarkAnalyze("Société Générale", b) }
func BenchmarkAnalyzeAscii(b *testing.B)     { benchmarkAnalyze("Holy Moly #7!", b) }
func BenchmarkAnalyzeNonLatin(b *testing.B)  { benchmarkAnalyze("תל אביב-יפו", b) }

func benchmarkAnalyzeBytes(s []byte, b *testing.B) {
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		AnalyzeBytes(s)
	}
}

func BenchmarkAnalyzeBytesDiacritic(b *testing.B) {
	benchmarkAnalyzeBytes([]byte("Société Générale"), b)
}
func BenchmarkAnalyzeBytesAscii(b *testing.B) { benchmarkAnalyzeBytes([]byte("Holy Moly #7!"), b) }
func BenchmarkAnalyzeBytesNonLatin(b *testing.B) {
	benchmarkAnalyzeBytes([]byte("תל אביב-יפו"), b)
}
