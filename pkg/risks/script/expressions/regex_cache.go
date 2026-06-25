package expressions

import (
	"regexp"
	"sync"
)

// regexCache memoises compiled regexes. The value/method-reference patterns used
// during expression evaluation are a tiny fixed set of constant strings, but
// were being recompiled on every evaluation (per value, per rule, per asset),
// which dominated regex allocation in the analysis profile. Caching them removes
// that cost while keeping behaviour identical. Safe for the parallel rule runner.
var regexCache sync.Map // pattern string -> *regexp.Regexp

func cachedRegexp(pattern string) *regexp.Regexp {
	if v, ok := regexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re := regexp.MustCompile(pattern)
	regexCache.Store(pattern, re)
	return re
}
