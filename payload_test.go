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

package license

import (
	"encoding/json"
	"strings"
	"time"

	sigar "github.com/cloudfoundry/gosigar"
	. "gopkg.in/check.v1"
)

type PayloadSuite struct{}

var _ = Suite(&PayloadSuite{})

func (s *PayloadSuite) TestMarshalUnmarshal(c *C) {
	p := Payload{
		ClusterID:  "cluster-123",
		Expiration: time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
		MaxNodes:   3,
		MaxCores:   8,
	}

	marshaled, err := json.Marshal(p)
	c.Assert(err, IsNil)

	// make sure expiration, max nodes and max cores were marshaled as strings
	c.Assert(strings.Contains(string(marshaled), `"cluster-123"`), Equals, true)
	c.Assert(strings.Contains(string(marshaled), `"2000-01-01T00:00:00Z"`), Equals, true)
	c.Assert(strings.Contains(string(marshaled), `3`), Equals, true)
	c.Assert(strings.Contains(string(marshaled), `8`), Equals, true)

	var unmarshaled Payload
	err = json.Unmarshal(marshaled, &unmarshaled)
	c.Assert(err, IsNil)

	// make sure we unmarshaled it correctly
	c.Assert(unmarshaled.ClusterID, Equals, "cluster-123")
	c.Assert(unmarshaled.Expiration, Equals, time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC))
	c.Assert(unmarshaled.MaxNodes, Equals, 3)
	c.Assert(unmarshaled.MaxCores, Equals, 8)
}

func (s *PayloadSuite) TestUnmarshalCustomerLicense(c *C) {
	l := `{"cluster_id": "4fea07ba370f389b", "expiration": "2016-12-31 00:00:00", "maxnodes": "17", "maxcores": "32"}`

	var unmarshaled Payload
	err := json.Unmarshal([]byte(l), &unmarshaled)
	c.Assert(err, IsNil)

	// make sure it got unmarshaled correctly
	c.Assert(unmarshaled.ClusterID, Equals, "4fea07ba370f389b")
	c.Assert(unmarshaled.Expiration, Equals, time.Date(2016, time.December, 31, 0, 0, 0, 0, time.UTC))
	c.Assert(unmarshaled.MaxNodes, Equals, 17)
	c.Assert(unmarshaled.MaxCores, Equals, 32)
}

func (s *PayloadSuite) TestMarshalUnmarshalOptional(c *C) {
	p := Payload{
		ClusterID:  "cluster-123",
		Expiration: time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC),
	}

	marshaled, err := json.Marshal(p)
	c.Assert(err, IsNil)

	// no zero values for max nodes and other fields should be present
	c.Assert(string(marshaled), Equals, `{"cluster_id":"cluster-123","expiration":"2000-01-01T00:00:00Z"}`)

	var unmarshaled Payload
	err = json.Unmarshal(marshaled, &unmarshaled)
	c.Assert(err, IsNil)

	// max nodes and max cores should be 0
	c.Assert(unmarshaled.MaxNodes, Equals, 0)
	c.Assert(unmarshaled.MaxCores, Equals, 0)
}

func (s *PayloadSuite) TestCheckCount(c *C) {
	tcs := []struct {
		name     string
		maxNodes int
		count    int
		ok       bool
	}{
		{
			name:     "license with max nodes 10 allows 3 nodes",
			maxNodes: 10,
			count:    3,
			ok:       true,
		},
		{
			name:     "license with max nodes 1 prohibits 3 nodes",
			maxNodes: 1,
			count:    3,
			ok:       false,
		},
		{
			name:     "license with max nodes 3 allows 3 nodes",
			maxNodes: 3,
			count:    3,
			ok:       true,
		},
		{
			name:     "license with max nodes 0 allows any number of nodes",
			maxNodes: 0,
			count:    3,
			ok:       true,
		},
	}
	for _, tc := range tcs {
		err := Payload{MaxNodes: tc.maxNodes}.CheckCount(tc.count)
		c.Assert(err == nil, Equals, tc.ok, Commentf("%v failed", tc.name))
	}
}

func (s *PayloadSuite) TestCheckCPU(c *C) {
	tcs := []struct {
		name     string
		maxCores int
		count    int
		ok       bool
	}{
		{
			name:     "license with max cores 10 allows 3 CPUs",
			maxCores: 10,
			count:    3,
			ok:       true,
		},
		{
			name:     "license with max cores 1 prohibits 3 CPUs",
			maxCores: 1,
			count:    3,
			ok:       false,
		},
		{
			name:     "license with max cores 3 allows 3 CPUs",
			maxCores: 3,
			count:    3,
			ok:       true,
		},
		{
			name:     "license with max cores 0 allows any number of CPUs",
			maxCores: 0,
			count:    3,
			ok:       true,
		},
	}
	for _, tc := range tcs {
		cpus := sigar.CpuList{}
		for i := 0; i < tc.count; i++ {
			cpus.List = append(cpus.List, sigar.Cpu{})
		}
		err := Payload{MaxCores: tc.maxCores}.CheckCPU(cpus)
		c.Assert(err == nil, Equals, tc.ok, Commentf("%v failed", tc.name))
	}
}

func (s *PayloadSuite) TestCheckInstanceTypes(c *C) {
	tcs := []struct {
		name          string
		maxCores      int
		instanceTypes []string
		ok            bool
	}{
		{
			name:          "license with max cores 2 does not support m3.l, m3.xl and c3.xl",
			maxCores:      2,
			instanceTypes: []string{"m3.large", "m3.xlarge", "c3.xlarge"},
			ok:            false,
		},
		{
			name:          "license with max cores 4 supports all of m3.l, m3.xl and c3.xl",
			maxCores:      4,
			instanceTypes: []string{"m3.large", "m3.xlarge", "c3.xlarge"},
			ok:            true,
		},
		{
			name:          "license with max cores 4 does not support c3.2xl",
			maxCores:      4,
			instanceTypes: []string{"c3.2xlarge", "i2.2xlarge"},
			ok:            false,
		},
		{
			name:          "license with max cores 0 supports all instance types",
			maxCores:      0,
			instanceTypes: []string{"m3.large", "c3.2xlarge", "i2.2xlarge"},
			ok:            true,
		},
	}
	for _, tc := range tcs {
		err := Payload{MaxCores: tc.maxCores}.CheckInstanceTypes(tc.instanceTypes)
		c.Assert(err == nil, Equals, tc.ok, Commentf("%v failed", tc.name))
	}
}

func (s *PayloadSuite) TestFilterInstanceTypes(c *C) {
	tcs := []struct {
		name          string
		maxCores      int
		instanceTypes []string
		expected      []string
	}{
		{
			name:          "license with max cores 2 supports only m3.l",
			maxCores:      2,
			instanceTypes: []string{"m3.large", "m3.xlarge", "c3.xlarge"},
			expected:      []string{"m3.large"},
		},
		{
			name:          "license with max cores 4 supports all of m3.l, m3.xl and c3.xl",
			maxCores:      4,
			instanceTypes: []string{"m3.large", "m3.xlarge", "c3.xlarge"},
			expected:      []string{"m3.large", "m3.xlarge", "c3.xlarge"},
		},
		{
			name:          "license with max cores 4 does not support c3.2xl and i2.2xl",
			maxCores:      4,
			instanceTypes: []string{"c3.2xlarge", "i2.2xlarge"},
			expected:      []string{},
		},
		{
			name:          "license with max cores 0 supports all instance types",
			maxCores:      0,
			instanceTypes: []string{"m3.large", "c3.2xlarge", "i2.2xlarge"},
			expected:      []string{"m3.large", "c3.2xlarge", "i2.2xlarge"},
		},
	}
	for _, tc := range tcs {
		filtered := Payload{MaxCores: tc.maxCores}.FilterInstanceTypes(tc.instanceTypes)
		c.Assert(filtered, DeepEquals, tc.expected, Commentf("%v failed", tc.name))
	}
}
