package nanoca

import (
	"fmt"
	"net/http"
)

const (
	// ACMEProblemTypePrefix is the URN prefix for ACME error types
	ACMEProblemTypePrefix = "urn:ietf:params:acme:error:"

	// ACME error type constants as defined in RFC 8555 Section 6.7
	accountDoesNotExistErr   = ACMEProblemTypePrefix + "accountDoesNotExist"
	badCSRErr                = ACMEProblemTypePrefix + "badCSR"
	badNonceErr              = ACMEProblemTypePrefix + "badNonce"
	badSignatureAlgorithmErr = ACMEProblemTypePrefix + "badSignatureAlgorithm"
	invalidContactErr        = ACMEProblemTypePrefix + "invalidContact"
	malformedErr             = ACMEProblemTypePrefix + "malformed"
	serverInternalErr        = ACMEProblemTypePrefix + "serverInternal"
	unauthorizedErr          = ACMEProblemTypePrefix + "unauthorized"
)

// Problem represents an RFC 7807/9457 compliant problem details object
// It implements the error interface
type Problem struct {
	// Type contains a URI reference that identifies the problem type
	Type string `json:"type,omitempty"`

	// Title is a short, human-readable summary of the problem type
	Title string `json:"title,omitempty"`

	// Status is the HTTP status code
	Status int `json:"status,omitempty"`

	// Detail is a human-readable explanation specific to this occurrence
	Detail string `json:"detail,omitempty"`

	// Instance is a URI reference that identifies the specific occurrence
	Instance string `json:"instance,omitempty"`

	// Identifier is the ACME identifier this problem relates to (for subproblems)
	Identifier *Identifier `json:"identifier,omitempty"`

	// Subproblems contains an array of sub-problems for compound errors
	Subproblems []Problem `json:"subproblems,omitempty"`

	// RFC 8555 Section 6.2: "The problem document returned with the error MUST include an
	// 'algorithms' field with an array of supported 'alg' values."
	Algorithms []string `json:"algorithms,omitempty"`
}

func (p *Problem) Error() string {
	return fmt.Sprintf("%s :: %s", p.Type, p.Detail)
}

func InternalServerError(detail string) *Problem {
	return &Problem{
		Type:   serverInternalErr,
		Detail: detail,
		Status: http.StatusInternalServerError,
	}
}

func Malformed(detail string) *Problem {
	return &Problem{
		Type:   malformedErr,
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

func BadNonce(detail string) *Problem {
	return &Problem{
		Type:   badNonceErr,
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

func BadCSR(detail string) *Problem {
	return &Problem{
		Type:   badCSRErr,
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

func BadSignatureAlgorithm(detail string, supportedAlgorithms []string) *Problem {
	// RFC 8555 Section 6.2: "If the client sends a JWS signed with an algorithm that the server
	// does not support, then the server MUST return an error with status code 400 (Bad Request)
	// and type 'urn:ietf:params:acme:error:badSignatureAlgorithm'. The problem document returned
	// with the error MUST include an 'algorithms' field with an array of supported 'alg' values."
	return &Problem{
		Type:       badSignatureAlgorithmErr,
		Detail:     detail,
		Status:     http.StatusBadRequest,
		Algorithms: supportedAlgorithms,
	}
}

func InvalidContact(detail string) *Problem {
	return &Problem{
		Type:   invalidContactErr,
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

func Unauthorized(detail string) *Problem {
	return &Problem{
		Type:   unauthorizedErr,
		Detail: detail,
		Status: http.StatusForbidden,
	}
}

func AccountDoesNotExist(detail string) *Problem {
	return &Problem{
		Type:   accountDoesNotExistErr,
		Detail: detail,
		Status: http.StatusBadRequest,
	}
}

func MethodNotAllowed(detail string) *Problem {
	return &Problem{
		Type:   malformedErr, // Using malformed as it's the closest match
		Detail: detail,
		Status: http.StatusMethodNotAllowed,
	}
}

func UnsupportedMediaTypeProblem(detail string) *Problem {
	return &Problem{
		Type:   malformedErr,
		Detail: detail,
		Status: http.StatusUnsupportedMediaType,
	}
}

func RequestTooLarge(detail string) *Problem {
	return &Problem{
		Type:   malformedErr,
		Detail: detail,
		Status: http.StatusRequestEntityTooLarge,
	}
}
