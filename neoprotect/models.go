package neoprotect

import (
	"time"
)

type IPAddressModel struct {
	IPv4     string      `json:"ipv4"`
	Settings *IPSettings `json:"settings,omitempty"`
}

type IPSettings struct {
	AutoMitigation bool `json:"autoMitigation"`
}

type AttackSignature struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	StartedAt *time.Time `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt"`
	PPSPeak   int64      `json:"ppsPeak"`
	BPSPeak   int64      `json:"bpsPeak"`
}

type Attack struct {
	ID               string            `json:"id"`
	DstAddressString string            `json:"dstAddressString"`
	DstAddress       *IPAddressModel   `json:"dstAddress"`
	Signatures       []AttackSignature `json:"signatures"`
	StartedAt        *time.Time        `json:"startedAt"`
	EndedAt          *time.Time        `json:"endedAt"`
	SampleRate       int64             `json:"sampleRate"`
}

type AttackStats struct {
	ID                    string     `json:"id"`
	PacketsTotal          int64      `json:"packetsTotal"`
	SourceIpsTotal        int64      `json:"sourceIpsTotal"`
	SourcePortsTotal      int64      `json:"sourcePortsTotal"`
	DestinationPortsTotal int64      `json:"destinationPortsTotal"`
	SourceCountriesTotal  int64      `json:"sourceCountriesTotal"`
	SourceAsnsTotal       int64      `json:"sourceAsnsTotal"`
	ProtocolsTotal        int64      `json:"protocolsTotal"`
	PacketLengthsTotal    int64      `json:"packetLengthsTotal"`
	TTLsTotal             int64      `json:"ttlsTotal"`
	CreatedAt             *time.Time `json:"createdAt"`
	UpdatedAt             *time.Time `json:"updatedAt"`

	SourceIps        []byte `json:"sourceIps"`
	SourcePorts      []byte `json:"sourcePorts"`
	DestinationPorts []byte `json:"destinationPorts"`
	SourceCountries  []byte `json:"sourceCountries"`
	SourceAsns       []byte `json:"sourceAsns"`
	Protocols        []byte `json:"protocols"`
	PacketLengths    []byte `json:"packetLengths"`
	TTLs             []byte `json:"ttls"`
	Payloads         []byte `json:"payloads"`
}

// Equal compares two Attack objects to determine if they are equal
func (a *Attack) Equal(other *Attack) bool {
	if a == nil || other == nil {
		return a == other
	}

	if a.ID != other.ID || a.DstAddressString != other.DstAddressString {
		return false
	}

	if !timeEqual(a.StartedAt, other.StartedAt) || !timeEqual(a.EndedAt, other.EndedAt) {
		return false
	}

	if len(a.Signatures) != len(other.Signatures) {
		return false
	}

	aSignatures := make(map[string]AttackSignature)
	for _, sig := range a.Signatures {
		aSignatures[sig.ID] = sig
	}

	for _, sig := range other.Signatures {
		aSig, ok := aSignatures[sig.ID]
		if !ok {
			return false
		}

		if aSig.Name != sig.Name || aSig.PPSPeak != sig.PPSPeak || aSig.BPSPeak != sig.BPSPeak {
			return false
		}

		if !timeEqual(aSig.StartedAt, sig.StartedAt) || !timeEqual(aSig.EndedAt, sig.EndedAt) {
			return false
		}
	}

	return true
}

func timeEqual(t1, t2 *time.Time) bool {
	if t1 == nil && t2 == nil {
		return true
	}
	if t1 == nil || t2 == nil {
		return false
	}
	return t1.Equal(*t2)
}

// IsActive returns true if the attack is currently active (no EndedAt timestamp)
func (a *Attack) IsActive() bool {
	return a.EndedAt == nil
}

// Duration returns the duration of the attack
func (a *Attack) Duration() time.Duration {
	if a.StartedAt == nil {
		return 0
	}

	endTime := time.Now()
	if a.EndedAt != nil {
		endTime = *a.EndedAt
	}

	return endTime.Sub(*a.StartedAt)
}

// GetPeakBPS returns the peak bits per second across all signatures
func (a *Attack) GetPeakBPS() int64 {
	var peak int64
	for _, sig := range a.Signatures {
		if sig.BPSPeak > peak {
			peak = sig.BPSPeak
		}
	}
	return peak
}

// GetPeakPPS returns the peak packets per second across all signatures
func (a *Attack) GetPeakPPS() int64 {
	var peak int64
	for _, sig := range a.Signatures {
		if sig.PPSPeak > peak {
			peak = sig.PPSPeak
		}
	}
	return peak
}

// GetSignatureNames returns all unique signature names
func (a *Attack) GetSignatureNames() []string {
	nameMap := make(map[string]struct{})
	for _, sig := range a.Signatures {
		nameMap[sig.Name] = struct{}{}
	}

	names := make([]string, 0, len(nameMap))
	for name := range nameMap {
		names = append(names, name)
	}

	return names
}

// CalculateDiff Calculates differences between this attack and a previous state
func (a *Attack) CalculateDiff(previous *Attack) map[string]interface{} {
	if previous == nil {
		return nil
	}

	diff := make(map[string]interface{})

	if previous.EndedAt == nil && a.EndedAt != nil {
		diff["ended"] = true
		diff["duration"] = a.Duration().String()
	}

	currentPeakBPS := a.GetPeakBPS()
	previousPeakBPS := previous.GetPeakBPS()
	if currentPeakBPS != previousPeakBPS {
		diff["bpsPeakChange"] = currentPeakBPS - previousPeakBPS
		diff["bpsPeakCurrent"] = currentPeakBPS
	}

	currentPeakPPS := a.GetPeakPPS()
	previousPeakPPS := previous.GetPeakPPS()
	if currentPeakPPS != previousPeakPPS {
		diff["ppsPeakChange"] = currentPeakPPS - previousPeakPPS
		diff["ppsPeakCurrent"] = currentPeakPPS
	}

	previousSigs := make(map[string]struct{})
	for _, sig := range previous.Signatures {
		previousSigs[sig.ID] = struct{}{}
	}

	var newSignatures []string
	for _, sig := range a.Signatures {
		if _, exists := previousSigs[sig.ID]; !exists {
			newSignatures = append(newSignatures, sig.Name)
		}
	}

	if len(newSignatures) > 0 {
		diff["newSignatures"] = newSignatures
	}

	return diff
}
