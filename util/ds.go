package util

import (
	"reflect"
)

//go:generate msgp

type Config struct {
	Check_interval_seconds  float64   `yaml:"check_interval_seconds"`
	Http_server_port  string  `yaml:"http_server_port"`
	Log_path  string  `yaml:"log_path"`
	Excluded_users []string `yaml:"excluded_users"`
}
//type DataKey struct {
//	Pid     string		`json:"pid"`
//	Src     string		`json:"src"`
//	Dst     string		`json:"dst"`
//	TypeStr string		`json:"type"`
//}
type DataValue struct {
	User		string
	Name        string  //cmd of process
	Status      string
	Create_time string
	End_time    string
}
func (x DataValue) IsStructureEmpty() bool {
	return reflect.DeepEqual(x, DataValue{})
}
type TCPInfo struct{
	Laddr  string
	Raddr  string
	Status string
}
type Process struct{
	User string
	Pid  string
	Cmd  string
}
