package main

import (
	"flag"
	"log"
	"os"

	"github.com/fa33az/polysmuggler/mutator"
	"github.com/fa33az/polysmuggler/proxy"
)

func main() {
	bindAddr := flag.String("listen", "127.0.0.1:8080", "Local address to bind proxy listener")
	target := flag.String("target", "", "Target URL (e.g. https://target.com) to reverse proxy and mutate requests for")
	headerCase := flag.Bool("case", true, "Enable polymorphic header casing strategy")
	chunkedObfuscate := flag.Bool("obfuscate", true, "Enable chunked Transfer-Encoding obfuscation strategy")
	unicodeHomoglyph := flag.Bool("homoglyph", false, "Enable unicode homoglyph translation for query params")
	smuggleCLTE := flag.Bool("clte", false, "Enable Content-Length / Transfer-Encoding (CL.TE) smuggling header order")
	smuggleTECL := flag.Bool("tecl", false, "Enable Transfer-Encoding / Content-Length (TE.CL) smuggling header order")
	delayChunks := flag.Int("delay", 0, "Delay in milliseconds between chunk delivery (0 for none)")
	verbose := flag.Bool("v", false, "Enable verbose output logging")

	flag.Parse()

	// Build Strategy
	strat := mutator.Strategy{
		HeaderCase:       *headerCase,
		ChunkedObfuscate: *chunkedObfuscate,
		UnicodeHomoglyph: *unicodeHomoglyph,
		SmuggleCLTE:      *smuggleCLTE,
		SmuggleTECL:      *smuggleTECL,
		DelayChunksMs:    *delayChunks,
	}

	// Create and start Proxy
	cfg := proxy.Config{
		BindAddr:     *bindAddr,
		StaticTarget: *target,
		Strategy:     strat,
		Verbose:      *verbose,
	}

	p := proxy.NewProxy(cfg)

	log.Printf("[*] Polysmuggler initialized successfully.")
	log.Printf("[*] Active Strategies: CaseRandomization=%t, ChunkObfuscation=%t, UnicodeHomoglyphs=%t, CL.TE=%t, TE.CL=%t",
		strat.HeaderCase, strat.ChunkedObfuscate, strat.UnicodeHomoglyph, strat.SmuggleCLTE, strat.SmuggleTECL)

	if err := p.Start(); err != nil {
		log.Fatalf("[-] Critical error in proxy: %v", err)
		os.Exit(1)
	}
}
