package dyndnsgo

type Config struct {
	Credentials  map[string]string
	Nsupdatekeys map[string]map[string]string
	Hostnames    map[string]string
}


