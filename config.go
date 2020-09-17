package main


type Config struct {
	Global struct{
		Address string
		Drive         string
		Interval      string
		Collector   []string
		TimeOut       int
	}
}
