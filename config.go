package domainrouter

type Config struct {
	General struct {
		AnnouncePublic bool   `yaml:"announce"`
		HealthEndpoint string `yaml:"healthz"`
	} `yaml:"general"`
	Server struct {
		Port     int    `yaml:"port"`
		CertFile string `yaml:"certFile"`
		KeyFile  string `yaml:"keyFile"`
	} `yaml:"server"`
	Hosts []struct {
		Port    int      `yaml:"port"`
		Domains []string `yaml:"domains"`
		Public  bool     `yaml:"public"`
	} `yaml:"hosts"`
	RateLimit struct {
		Enabled       bool   `yaml:"enabled"`
		BucketSize    int    `yaml:"bucketSize"`
		RefillTicker  string `yaml:"refillTime"`
		CleanupTicker string `yaml:"cleanupTime"`
		BucketRefill  int    `yaml:"refillSize"`
	} `yaml:"rateLimit"`
	Logging struct {
		Level    string `yaml:"level"`
		Pretty   bool   `yaml:"pretty"`
		Path     string `yaml:"path"`
		Requests bool   `yaml:"requests"`
	} `yaml:"logging"`
}
