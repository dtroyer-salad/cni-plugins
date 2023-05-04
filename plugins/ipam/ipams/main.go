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
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/containernetworking/cni/pkg/version"
	"github.com/containernetworking/plugins/pkg/ipam"
	bv "github.com/containernetworking/plugins/pkg/utils/buildversion"
)

// The top-level network config - IPAM plugins are passed the full configuration
// of the calling plugin, not just the IPAM section. We can't use types.NetConfig
// because of changing the IPAM type.

// Net is used for creating the sub-plugin JSON stdin data
type Net struct {
	CNIVersion string `json:"cniVersion"`

	Name         string          `json:"name,omitempty"`
	Type         string          `json:"type,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	IPAM         *IPAMConfig     `json:"ipam,omitempty"`
	DNS          types.DNS       `json:"dns"`

	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types.Result           `json:"-"`

	RuntimeConfig struct {
		IPs []string `json:"ips,omitempty"`
	} `json:"runtimeConfig,omitempty"`
	Args *struct {
		A *IPAMArgs `json:"cni"`
	} `json:"args"`
}

// NetList handles the stdin data for the ipams format
type NetList struct {
	CNIVersion string `json:"cniVersion"`

	Name         string          `json:"name"`
	Type         string          `json:"type,omitempty"`
	Capabilities map[string]bool `json:"capabilities,omitempty"`
	IPAM         *IPAMList       `json:"ipam"`
	DNS          types.DNS       `json:"dns"`

	RawPrevResult map[string]interface{} `json:"prevResult,omitempty"`
	PrevResult    types.Result           `json:"-"`

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
	*Range
	Name string
	Type string `json:"type"`
	// static
	Routes    []*types.Route `json:"routes,omitempty"`
	Addresses []Address      `json:"addresses,omitempty"`
	DNS       types.DNS      `json:"dns,omitempty"`
	// host-local
	DataDir    string     `json:"dataDir,omitempty"`
	ResolvConf string     `json:"resolvConf,omitempty"`
	Ranges     []RangeSet `json:"ranges,omitempty"`
	IPArgs     []net.IP   `json:"-"` // Requested IPs from CNI_ARGS, args and capabilities
	// dhcp
	DaemonSocketPath string          `json:"daemonSocketPath,omitempty"`
	ProvideOptions   []ProvideOption `json:"provide,omitempty"`
	RequestOptions   []RequestOption `json:"request,omitempty"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP      types.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY types.UnmarshallableString `json:"gateway,omitempty"`
}

type IPAMArgs struct {
	IPs []string `json:"ips,omitempty"`
}

type Address struct {
	AddressStr string    `json:"address,omitempty"`
	Gateway    net.IP    `json:"gateway,omitempty"`
	Address    net.IPNet `json:"-"`
	Version    string    `json:"-"`
}

type RangeSet []Range

type Range struct {
	RangeStart net.IP      `json:"rangeStart,omitempty"` // The first ip, inclusive
	RangeEnd   net.IP      `json:"rangeEnd,omitempty"`   // The last ip, inclusive
	Subnet     types.IPNet `json:"subnet,omitempty"`
	Gateway    net.IP      `json:"gateway,omitempty"`
}
type DHCPOption string

type ProvideOption struct {
	Option DHCPOption `json:"option,omitempty"`

	Value           string `json:"value,omitempty"`
	ValueFromCNIArg string `json:"fromArg,omitempty"`
}

type RequestOption struct {
	SkipDefault bool `json:"skipDefault,omitempty"`

	Option DHCPOption `json:"option,omitempty"`
}

func main() {
	// f, err := os.OpenFile("/tmp/ipams.log", os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	// defer f.Close()
	// log.SetOutput(f)

	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, bv.BuildString("ipams"))
}

// parseConfig parses the supplied configuration (and prevResult) from stdin.
func parseConfig(stdin []byte) (*NetList, error) {
	conf := NetList{}
	// log.Printf("stdin: %s\n", stdin)
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
		CNIVersion:    conf.CNIVersion,
		Name:          conf.Name,
		Type:          conf.Type,
		Capabilities:  conf.Capabilities,
		IPAM:          ipam,
		DNS:           conf.DNS,
		RawPrevResult: conf.RawPrevResult,
		RuntimeConfig: conf.RuntimeConfig,
		Args:          conf.Args,
	}

	subJSON, err := json.Marshal(subConf)
	if err != nil {
		// log.Printf("Error creating stdin for %s: %s\n", ipam.Type, err)
	}
	return subJSON, err
}

// Remove CNI_ARGS from environment
func cleanEnv() error {
	cniArgs := os.Getenv("CNI_ARGS")
	var newArgs []string
	for _, kv := range strings.Split(cniArgs, ";") {
		env := strings.Split(kv, "=")
		if env[0] != "IP" {
			newArgs = append(newArgs, kv)
		}
	}
	return os.Setenv("CNI_ARGS", strings.Join(newArgs, ";"))
}

func cmdAdd(args *skel.CmdArgs) error {
	// log.Printf("Starting ipams CNI: add\n")
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		// log.Printf("Failed to parse stdin: %s\n", err)
		return err
	}

	mergedResult := &current.Result{}
	if conf.PrevResult != nil {
		// Convert the PrevResult to a concrete Result type that can be modified.
		prevResult, err := current.GetResult(conf.PrevResult)
		if err != nil {
			return fmt.Errorf("failed to convert prevResult: %v", err)
		}
		mergedResult = prevResult
	}

	for _, i := range *conf.IPAM.IPAMS {
		subJSON, err := getSubJSON(conf, &i)
		if err != nil {
			// log.Printf("Failed to make %s JSON: %s\n", i.Type, err)
			return err
		}
		// log.Printf("%s subJSON: %s\n", i.Type, subJSON)

		// Filter the environment passed to the sub-plugin
		cleanEnv()

		// Run the IPAM plugin and get back the config to apply
		subResult, err := ipam.ExecAdd(i.Type, subJSON)
		if err != nil {
			// log.Printf("Failed to run %s plugin add: %s\n", i.Type, err)
			return fmt.Errorf("%v", err)
		}

		// Invoke ipam del if err to avoid ip leak
		defer func() {
			if err != nil {
				// log.Printf("Cleaning up %s after error %s\n", i.Type, err)
				ipam.ExecDel(i.Type, subJSON)
			}
		}()

		// Convert whatever the IPAM result was into the current Result type
		result, err := current.NewResultFromResult(subResult)
		if err != nil {
			// log.Printf("Failed to get result %s add: %s\n", i.Type, err)
			return err
		}
		// log.Printf("result: %+v\n", result)

		// Merge results
		mergedResult.CNIVersion = result.CNIVersion
		for _, ifc := range result.Interfaces {
			mergedResult.Interfaces = append(mergedResult.Interfaces, ifc)
		}
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
	// log.Printf("mergedResult: %+v\n", mergedResult)

	return types.PrintResult(mergedResult, mergedResult.CNIVersion)
}

func cmdCheck(args *skel.CmdArgs) error {
	log.Printf("Starting ipams CNI: check\n")
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		// log.Printf("Failed to parse stdin: %s\n", err)
		return err
	}

	var errResult error
	for _, i := range *conf.IPAM.IPAMS {
		subJSON, err := getSubJSON(conf, &i)
		if err != nil {
			// log.Printf("Failed to make %s JSON\n", i.Type)
			errResult = err
			continue
		}
		// log.Printf("%s subJSON: %s\n", i.Type, subJSON)

		// Run the IPAM plugin
		err = ipam.ExecCheck(i.Type, subJSON)
		if err != nil {
			// log.Printf("Failed to run %s plugin check\n", i.Type)
			errResult = err
			continue
		}
	}

	return errResult
}

func cmdDel(args *skel.CmdArgs) error {
	// log.Printf("Starting ipams CNI: del\n")
	conf, err := parseConfig(args.StdinData)
	if err != nil {
		// log.Printf("Failed to parse stdin: %s\n", err)
		return err
	}

	var errResult error
	for _, i := range *conf.IPAM.IPAMS {
		subJSON, err := getSubJSON(conf, &i)
		if err != nil {
			// log.Printf("Failed to make %s JSON\n", i.Type)
			errResult = err
			continue
		}
		// log.Printf("%s subJSON: %s\n", i.Type, subJSON)

		// Run the IPAM plugin
		err = ipam.ExecDel(i.Type, subJSON)
		if err != nil {
			// log.Printf("Failed to run %s plugin del\n", i.Type)
			errResult = err
			continue
		}
	}

	return errResult
}
