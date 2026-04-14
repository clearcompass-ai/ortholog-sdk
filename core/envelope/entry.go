package envelope

type Entry struct {
	Header        ControlHeader
	DomainPayload []byte
}
