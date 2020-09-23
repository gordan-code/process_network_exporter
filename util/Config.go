package util

//go:generate msgp

type Config struct {
	Check_interval_seconds float64  `yaml:"check_interval_seconds"`
	Http_server_port       string   `yaml:"http_server_port"`
	Log_path               string   `yaml:"log_path"`
	Excluded_users         []string `yaml:"excluded_users"`
}

type TCPInfo struct {
	Laddr  string
	Raddr  string
	Status string
}
type Process struct {
	User string
	Pid  string
	Cmd  string
}
