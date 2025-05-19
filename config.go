package domainrouter

type Config struct {
	General struct {
		AnnouncePublic bool   `yaml:"announce"`
		HealthEndpoint string `yaml:"healthz"`
	} `yaml:"general"`
	Server struct {
		Port int `yaml:"port"`
		Ssl  struct {
			Enabled  bool   `yaml:"enabled"`
			CertFile string `yaml:"certFile"`
			KeyFile  string `yaml:"keyFile"`
		} `yaml:"ssl"`
	} `yaml:"server"`
	Hosts []struct {
		Port    int      `yaml:"port"`
		Remotes  []string `yaml:"remotes"`
		Domains []string `yaml:"domains"`
		Public  bool     `yaml:"public"`
		Secure  bool     `yaml:"secure"`
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
		Requests bool   `yaml:"requests"`
		File     struct {
			Enabled    bool   `yaml:"enabled"`
			Path       string `yaml:"path"`
			MaxAge     int    `yaml:"maxAge"`
			MaxBackups int    `yamls:"maxBackups"`
		} `yaml:"file"`
	} `yaml:"logging"`
}
