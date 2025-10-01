package domainrouter

type Location struct {

}

type Config struct {
	Server struct {
		Port int `yaml:"port" kdl:"port"`
		Ssl  struct {
			Enabled  bool   `yaml:"enabled" kdl:"enabled"`
			CertFile string `yaml:"certFile" kdl:"cert-file"`
			KeyFile  string `yaml:"keyFile" kdl:"key-file"`
			Acme     struct {
				Enabled       bool   `yaml:"enabled" kdl:"enabled"`
				Email         string `yaml:"email" kdl:"email"`
				KeyFile       string `yaml:"keyFile" kdl:"key-file"`
				CADirURL      string `yaml:"caDirUrl" kdl:"ca-dir-url"`
				Http01Port    string `yaml:"http01Port" kdl:"http-01-port"`
				TlsAlpn01Port string `yaml:"tlsAlpn01Port" kdl:"tls-apln01-port"`
				RenewTime     string `yaml:"renewTime" kdl:"renew-time"`
			} `yaml:"acme" kdl:"acme"`
		} `yaml:"ssl" kdl:"ssl"`
	} `yaml:"server" kdl:"server"`
	
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
