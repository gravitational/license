/*
Copyright 2017 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package checks

import (
	"github.com/gravitational/license"
	"github.com/gravitational/license/constants"

	sigar "github.com/cloudfoundry/gosigar"
	"github.com/gravitational/trace"
)

// CheckCount checks if the license supports the provided number of servers
func CheckCount(p license.Payload, count int) error {
	if p.MaxNodes != 0 && count > p.MaxNodes {
		return trace.BadParameter(
			"the license allows maximum of %v nodes, requested: %v", p.MaxNodes, count)
	}
	return nil
}

// CheckCPU checks if the license supports the provided number of CPUs
func CheckCPU(p license.Payload, cpu sigar.CpuList) error {
	count := len(cpu.List)
	if p.MaxCores != 0 && count > p.MaxCores {
		return trace.BadParameter(
			"the license allows maximum of %v CPUs, requested: %v", p.MaxCores, count)
	}
	return nil
}

// CheckInstanceTypes checks if the license supports all of the provided AWS instance types
func CheckInstanceTypes(p license.Payload, instanceTypes []string) error {
	supported := make(map[string]struct{})
	for _, t := range FilterInstanceTypes(p, instanceTypes) {
		supported[t] = struct{}{}
	}
	for _, t := range instanceTypes {
		if _, ok := supported[t]; !ok {
			return trace.BadParameter(
				"the license does not support instance type: %v", t)
		}
	}
	return nil
}

// FilterInstanceTypes retuns a subset of the provided AWS instance types supported by the license
func FilterInstanceTypes(p license.Payload, instanceTypes []string) []string {
	if p.MaxCores == 0 {
		return instanceTypes
	}
	supported := []string{}
	for _, t := range instanceTypes {
		for name, cores := range constants.EC2InstanceTypes {
			if name == t && cores <= p.MaxCores {
				supported = append(supported, t)
			}
		}
	}
	return supported
}
