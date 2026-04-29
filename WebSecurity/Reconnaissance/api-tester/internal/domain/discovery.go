package domain

// MethodDiscovery records how a single HTTP method behaved for one endpoint.
type MethodDiscovery struct {
	Method              string
	StatusCode          int
	QueryParamsAccepted []string
	BodyFieldsAccepted  []string
	Notes               string
}

// EndpointDiscovery represents a discovered endpoint and the methods it supports.
type EndpointDiscovery struct {
	Path    string
	URL     string
	Source  string
	Methods []MethodDiscovery
}
