package compose

import "gopkg.in/yaml.v3"

// composeFile is the subset of a docker-compose file we model. Polymorphic fields
// (ports / depends_on / networks / environment can each be a list or a map) are
// kept as raw yaml.Node and normalised by helpers.
type composeFile struct {
	Services map[string]composeService `yaml:"services"`
	Networks map[string]networkConfig  `yaml:"networks"`
}

type composeService struct {
	Image       string      `yaml:"image"`
	Build       yaml.Node   `yaml:"build"`       // string or map -> custom-developed
	Ports       []yaml.Node `yaml:"ports"`       // "host:container" strings or long-form maps
	Expose      []string    `yaml:"expose"`      // container-only ports (not host-published)
	DependsOn   yaml.Node   `yaml:"depends_on"`  // list or map(keys)
	Networks    yaml.Node   `yaml:"networks"`    // list or map(keys)
	Environment yaml.Node   `yaml:"environment"` // list of "K=V" or map
}

type networkConfig struct {
	Internal bool `yaml:"internal"`
}
