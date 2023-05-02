// Copyright 2018 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// The top-level network config - IPAM plugins are passed the full configuration
// of the calling plugin, not just the IPAM section.
type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	Type       string      `json:"type,omitempty"`
	IPAM       *IPAMConfig `json:"ipam"`
	DNS        types.DNS   `json:"dns"`

	RuntimeConfig struct {
		IPs []string `json:"ips,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

type NetList struct {
	Name       string    `json:"name"`
	CNIVersion string    `json:"cniVersion"`
	Type       string    `json:"type,omitempty"`
	IPAM       *IPAMList `json:"ipam"`
	DNS        types.DNS `json:"dns"`

	RuntimeConfig struct {
		IPs []string `json:"ips,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

type IPAMList struct {
	IPAMS *[]IPAMConfig `json:"ipams"`
}
type IPAMConfig struct {
	Name string
	Type string `json:"type"`
	// static
	Routes    []*types.Route `json:"routes"`
	Addresses []Address      `json:"addresses,omitempty"`
	DNS       types.DNS      `json:"dns"`
	// host-local
	DataDir    string     `json:"dataDir"`
	ResolvConf string     `json:"resolvConf"`
	Ranges     []RangeSet `json:"ranges"`
	IPArgs     []net.IP   `json:"-"` // Requested IPs from CNI_ARGS, args and capabilities
	// dhcp
	DaemonSocketPath string          `json:"daemonSocketPath"`
	ProvideOptions   []ProvideOption `json:"provide"`
	RequestOptions   []RequestOption `json:"request"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP      types.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY types.UnmarshallableString `json:"gateway,omitempty"`
}

type IPAMArgs struct {
	IPs []string `json:"ips"`
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

type RangeSet []Range

type Range struct {
	RangeStart net.IP      `json:"rangeStart,omitempty"` // The first ip, inclusive
	RangeEnd   net.IP      `json:"rangeEnd,omitempty"`   // The last ip, inclusive
	Subnet     types.IPNet `json:"subnet"`
	Gateway    net.IP      `json:"gateway,omitempty"`
}
type DHCPOption string

type ProvideOption struct {
	Option DHCPOption `json:"option"`

	Value           string `json:"value"`
	ValueFromCNIArg string `json:"fromArg"`
}

type RequestOption struct {
	SkipDefault bool `json:"skipDefault"`

	Option DHCPOption `json:"option"`
}

func main() {
	f, err := os.OpenFile("/tmp/ipams.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	log.SetOutput(f)

	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("ipams"))
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*NetList, error) {
	conf := NetList{}
	log.Printf("stdin: %s\n", stdin)
	if err := json.Unmarshal(stdin, &conf); err != nil {
		return nil, fmt.Errorf("failed to parse network configuration: %v", err)
	}
	if conf.IPAM == nil {
		return nil, fmt.Errorf("IPAM config missing 'ipam' key")
	}

	return &conf, nil
}

// Get subJSON for each plugin
func getSubJSON(conf *NetList, ipam *IPAMConfig) ([]byte, error) {
	// Need to build an appropriate input for the sub-plugins
	subConf := &Net{
		CNIVersion: conf.CNIVersion,
		Name:       conf.Name,
		Type:       conf.Type,
		IPAM:       ipam,
		DNS:        conf.DNS,
	}

	subJSON, err := json.Marshal(subConf)
	if err != nil {
		log.Printf("Error creating stdin for %s: %s\n", ipam.Type, err)
	}
	return subJSON, err
}

func cmdAdd(args *skel.CmdArgs) error {
	log.Printf("Starting ipams CNI: add\n")
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		log.Printf("Failed to parse stdin\n")
		return err
	}

	mergedResult := &current.Result{
		CNIVersion: current.ImplementedSpecVersion,
	}
	var errResult error
	for _, i := range *conf.IPAM.IPAMS {
		subJSON, err := getSubJSON(conf, &i)
		if err != nil {
			log.Printf("Failed to make %s JSON\n", i.Type)
			errResult = err
			continue
		}

		// Run the IPAM plugin and get back the config to apply
		subResult, err := ipam.ExecAdd(i.Type, subJSON)
		if err != nil {
			log.Printf("Failed to run %s plugin add\n", i.Type)
			errResult = err
			continue
		}

		// Invoke ipam del if err to avoid ip leak
		defer func() {
			if err != nil {
				ipam.ExecDel(i.Type, subJSON)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(subResult)
		if err != nil {
			errResult = err
			continue
		}
		log.Printf("result: %+v\n", result)

		// Merge results
		for _, ip := range result.IPs {
			mergedResult.IPs = append(mergedResult.IPs, ip)
		}
		for _, route := range result.Routes {
			mergedResult.Routes = append(mergedResult.Routes, route)
		}
		for _, ns := range result.DNS.Nameservers {
			mergedResult.DNS.Nameservers = append(mergedResult.DNS.Nameservers, ns)
		}
		for _, s := range result.DNS.Search {
			mergedResult.DNS.Search = append(mergedResult.DNS.Search, s)
		}
		for _, opt := range result.DNS.Options {
			mergedResult.DNS.Options = append(mergedResult.DNS.Options, opt)
		}
	}
	if errResult != nil {
		return errResult
	}
	log.Printf("mergedResult: %+v\n", mergedResult)

	return types.PrintResult(mergedResult, mergedResult.CNIVersion)
}

func cmdCheck(args *skel.CmdArgs) error {
	log.Printf("Starting ipams CNI: check\n")
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		log.Printf("Failed to parse stdin\n")
		return err
	}

	var errResult error
	for _, i := range *conf.IPAM.IPAMS {
		subJSON, err := getSubJSON(conf, &i)
		if err != nil {
			log.Printf("Failed to make %s JSON\n", i.Type)
			errResult = err
			continue
		}

		// Run the IPAM plugin
		err = ipam.ExecCheck(i.Type, subJSON)
		if err != nil {
			log.Printf("Failed to run %s plugin check\n", i.Type)
			errResult = err
			continue
		}
	}

	return errResult
}

func cmdDel(args *skel.CmdArgs) error {
	log.Printf("Starting ipams CNI: del\n")
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		log.Printf("Failed to parse stdin\n")
		return err
	}

	var errResult error
	for _, i := range *conf.IPAM.IPAMS {
		subJSON, err := getSubJSON(conf, &i)
		if err != nil {
			log.Printf("Failed to make %s JSON\n", i.Type)
			errResult = err
			continue
		}

		// Run the IPAM plugin
		err = ipam.ExecDel(i.Type, subJSON)
		if err != nil {
			log.Printf("Failed to run %s plugin del\n", i.Type)
			errResult = err
			continue
		}
	}

	return errResult
}
