package domainrouter

type Config struct {
	Server struct {
		Port int `yaml:"port"`
		Ssl  struct {
			Enabled  bool   `yaml:"enabled"`
			CertFile string `yaml:"certFile"`
			KeyFile  string `yaml:"keyFile"`
			Acme     struct {
				Enabled       bool   `yaml:"enabled"`
				Email         string `yaml:"email"`
				KeyFile       string `yaml:"keyFile"`
				CADirURL      string `yaml:"caDirUrl"`
				Http01Port    string `yaml:"http01Port"`
				TlsAlpn01Port string `yaml:"tlsAlpn01Port"`
				RenewTime     string `yaml:"renewTime"`
			} `yaml:"acme"`
		} `yaml:"ssl"`
	} `yaml:"server"`
	Hosts []struct {
		Port    int               `yaml:"port"`
		Remotes []string          `yaml:"remotes"`
		Domains []string          `yaml:"domains"`
		Secure  bool              `yaml:"secure"`
		Rewrite map[string]string `yaml:"rewrite"`
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
	Metrics struct {
		Enabled       bool   `yaml:"enabled"`
		File          string `yaml:"file"`
		BufferSize    int    `yaml:"bufferSize"`
		FlushInterval string `yaml:"flushInterval"`
	} `yaml:"metrics"`
}
