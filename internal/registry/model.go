package registry

import "time"

type IssuerRef struct {
	Name           string `json:"name"`
	Generation     uint64 `json:"generation"`
	Serial         string `json:"serial"`
	Fingerprint    string `json:"fingerprint"`
	RootGeneration uint64 `json:"rootGeneration"`
}

type Certificate struct {
	SchemaVersion     int        `json:"schemaVersion"`
	Serial            string     `json:"serial"`
	PKI               string     `json:"pki"`
	Issuer            string     `json:"issuer"`
	IssuerGeneration  uint64     `json:"issuerGeneration,omitempty"`
	IssuerSerial      string     `json:"issuerSerial,omitempty"`
	IssuerFingerprint string     `json:"issuerFingerprint,omitempty"`
	RootGeneration    uint64     `json:"rootGeneration,omitempty"`
	Type              string     `json:"type"`
	Name              string     `json:"name"`
	Subject           string     `json:"subject"`
	DNS               []string   `json:"dns,omitempty"`
	IP                []string   `json:"ip,omitempty"`
	URI               []string   `json:"uri,omitempty"`
	NotBefore         time.Time  `json:"notBefore"`
	NotAfter          time.Time  `json:"notAfter"`
	Certificate       string     `json:"certificate"`
	Status            string     `json:"status"`
	Reason            string     `json:"reason,omitempty"`
	RevokedAt         *time.Time `json:"revokedAt,omitempty"`
}

type Issuer struct {
	Name             string                      `json:"name"`
	Type             string                      `json:"type"`
	ActiveGeneration uint64                      `json:"activeGeneration"`
	Status           string                      `json:"status"`
	Generations      map[uint64]IssuerGeneration `json:"generations"`
}

type IssuerGeneration struct {
	Generation     uint64    `json:"generation"`
	RootGeneration uint64    `json:"rootGeneration"`
	Serial         string    `json:"serial"`
	Fingerprint    string    `json:"fingerprint"`
	CreatedAt      time.Time `json:"createdAt"`
	CRLNumber      uint64    `json:"crlNumber"`
}

type Root struct {
	ActiveGeneration uint64        `json:"activeGeneration"`
	TrustGenerations []uint64      `json:"trustGenerations"`
	Rotation         *RootRotation `json:"rotation,omitempty"`
}

type RootRotation struct {
	From, To  uint64
	Phase     string
	StartedAt time.Time
}
