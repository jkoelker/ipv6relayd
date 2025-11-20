package ifmon

// InterfaceEvent represents a link or address update surfaced by the
// shared interface monitor.
type InterfaceEvent struct {
	Reason  string
	IfIndex int
	IfName  string
}
