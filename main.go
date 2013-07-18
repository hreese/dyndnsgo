package main

import (
	"code.google.com/p/go.crypto/bcrypt"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	//"os"
	"strings"
)

var (
	config Config
)

/* 
 * check http request for credentials
 */
func ExtractCrendentials(req *http.Request) (user string, pass string, found bool) {
	found = false

	// Check for basic authorization header
	if authheader, ok := req.Header["Authorization"]; ok == true {
		// check of auth-type is Basic
		if strings.HasPrefix(authheader[0], "Basic ") {
			authvalue := strings.SplitN(authheader[0], " ", 2)
			// decode auth value
			if authvalue_dec, ok := base64.StdEncoding.DecodeString(authvalue[1]); ok == nil {
				// split user and password
				userpass := strings.SplitN(string(authvalue_dec), ":", 2)
				found, user, pass = true, userpass[0], userpass[1]
				return
			}
		}
	}

	// check for url-encoded credentials
	user, pass = req.FormValue("username"), req.FormValue("password")
	// only accept credentials of both parts are not empty
	if user != "" && pass != "" {
		found = true
		return
	}
	return "", "", false
}

/* Parse configuration in json format.
   Return Config and nil on success or empty Config and an error explaining all
   problems.
*/
func ReadConfig(configfile string) (Config, error) {
	var f Config
	var configerrors string

	// read config file
	c, err := ioutil.ReadFile(configfile)
	if err != nil {
		return Config{}, err
	}

	// decode JSON
	jsonerror := json.Unmarshal(c, &f)
	if jsonerror != nil {
		return Config{}, jsonerror
	}

	// check that every section contains at least one entry
	if len(f.Credentials) == 0 {
		configerrors += "No credentials.\n"
	}
	if len(f.Nsupdatekeys) == 0 {
		configerrors += "No nsupdatekeys.\n"
	}
	if len(f.Hostnames) == 0 {
		configerrors += "No hostnames.\n"
	}
	for hostname, user := range f.Hostnames {
		// check that each hostname has a corresponding nsupdate-key
		if _, present := f.Nsupdatekeys[hostname]; !present {
			configerrors += "Missing nsupdate-key for hostname " + hostname + "\n"
		}
		// check that each user in the hostname list has a corresponding password
		if _, present := f.Credentials[user]; !present {
			configerrors += "Missing credential for user " + user + "\n"
		}
	}

	// check that each nsupdate key hat either inline key or filename
	for hostname, hconfig := range f.Nsupdatekeys {
		_, has_key := hconfig["key"]
		_, has_file := hconfig["filename"]
		if has_key == false && has_file == false {
			configerrors += "nsupdate-key " + hostname + " has neither filename nor inline key.\n"
		}
	}

	if configerrors == "" {
		return f, nil
	} else {
		return Config{}, errors.New(configerrors)
	}
}

// dyndns-update-handler
func UpdateHandler(w http.ResponseWriter, req *http.Request) {
	var (
		pwhash, user, pass string
		userfound, foundpw bool
	)

	// parse url parameters
	req.ParseForm()
	ExtractOriginatingIP(req)

	// extract username and password from request
	if user, pass, userfound = ExtractCrendentials(req); !userfound {
		log.Print("Request without credentials")
		io.WriteString(w, "badauth")
		return
	}
	// check if user exists in local database
	if pwhash, foundpw = config.Credentials[user]; !foundpw {
		log.Print("User " + user + " not found in local database.")
		io.WriteString(w, "badauth")
		return
	}

	// compare passwords
	if bcrypt.CompareHashAndPassword([]byte(pwhash), []byte(pass)) != nil {
		log.Print("Password for user " + user + " does not match password from local database.")
		io.WriteString(w, "badauth")
		return
	} else {
		log.Print("User " + user + " authenticated for updates.")
	}

	hostnames := strings.Split(req.FormValue("hostname"), ",")

	//fmt.Printf("%+v\n", req.Header)
	fmt.Printf("%+v\n", hostnames)
}

func ExtractOriginatingIP(req *http.Request) (ip string, found bool) {
	var possible_ips []string

	// append ip from request
	possible_ips = append(possible_ips, strings.Split(req.RemoteAddr, ":")[0])

	// check for X-Forwarded-For-Header
	if authheader, ok := req.Header["X-Forwarded-For"]; ok == true {
		possible_ips = append(possible_ips, strings.Split(authheader[0], ", ")[0])
	}

	fmt.Printf("+++ %+v\n", possible_ips)

	for _, ip := range possible_ips {
		if !strings.HasPrefix("127.0.0.1", ip) && ip != "" {
			return ip, true
		}
	}

	return "", false
}

func main() {
	var err error

	// read config
	if config, err = ReadConfig("config.json"); err != nil {
		log.Fatal(err)
	}

	// add http handler
	http.HandleFunc("/nic/update", UpdateHandler)

	// start http server
	err = http.ListenAndServe(":12345", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
