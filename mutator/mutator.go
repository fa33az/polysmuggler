package mutator

import (
	"crypto/rand"
	"math/big"
	"strings"
)

// Strategy defines the active mutation strategies
type Strategy struct {
	HeaderCase        bool
	ChunkedObfuscate  bool
	UnicodeHomoglyph  bool
	SmuggleCLTE       bool
	SmuggleTECL       bool
	DelayChunksMs     int
}

// Mutator handles the execution of mutation strategies on HTTP requests
type Mutator struct {
	Strat Strategy
}

// NewMutator creates a new Mutator instance
func NewMutator(strat Strategy) *Mutator {
	return &Mutator{Strat: strat}
}

// RandomCase randomizes the casing of a header key
func (m *Mutator) RandomCase(key string) string {
	if !m.Strat.HeaderCase {
		return key
	}
	var builder strings.Builder
	for i := 0; i < len(key); i++ {
		char := key[i]
		if char >= 'a' && char <= 'z' {
			if randBool() {
				char = char - 32 // Convert to uppercase
			}
		} else if char >= 'A' && char <= 'Z' {
			if randBool() {
				char = char + 32 // Convert to lowercase
			}
		}
		builder.WriteByte(char)
	}
	return builder.String()
}

// ObfuscateTransferEncoding returns a mutated/obfuscated Transfer-Encoding header value
func (m *Mutator) ObfuscateTransferEncoding() (string, string) {
	if !m.Strat.ChunkedObfuscate {
		return "Transfer-Encoding", "chunked"
	}

	key := "Transfer-Encoding"
	val := "chunked"

	// Choose a random obfuscation style
	n := randInt(6)
	switch n {
	case 0:
		// Spacing trick
		val = " chunked"
	case 1:
		// Tab spacing
		val = "\tchunked"
	case 2:
		// Mixed case value
		val = "ChUnKeD"
	case 3:
		// Double value
		val = "chunked, chunked"
	case 4:
		// Custom key casing
		key = "X-Transfer-Encoding"
		val = "chunked"
	case 5:
		// Parameter injection
		val = "chunked; param=val"
	}
	return key, val
}

// TranslateUnicode replaces specific standard characters with Unicode homoglyphs to bypass simple regex WAFs
func (m *Mutator) TranslateUnicode(input string) string {
	if !m.Strat.UnicodeHomoglyph {
		return input
	}

	// Simple map of homoglyphs (Cyrillic equivalents)
	homoglyphs := map[rune]string{
		'a': "а", // Cyrillic small letter a
		'c': "с", // Cyrillic small letter es
		'e': "е", // Cyrillic small letter ie
		'i': "і", // Cyrillic small letter byelorussian-ukrainian i
		'j': "ј", // Cyrillic small letter je
		'o': "о", // Cyrillic small letter o
		'p': "р", // Cyrillic small letter er
		's': "ѕ", // Cyrillic small letter dze
		'x': "х", // Cyrillic small letter ha
		'y': "у", // Cyrillic small letter u
	}

	var builder strings.Builder
	for _, char := range input {
		if replacement, ok := homoglyphs[char]; ok && randBool() {
			builder.WriteString(replacement)
		} else {
			builder.WriteRune(char)
		}
	}
	return builder.String()
}

// Helper function to get random boolean
func randBool() bool {
	n, _ := rand.Int(rand.Reader, big.NewInt(2))
	return n.Int64() == 1
}

// Helper function to get random int up to max
func randInt(max int64) int64 {
	n, _ := rand.Int(rand.Reader, big.NewInt(max))
	return n.Int64()
}
