package models

type ApplicationEnrollmentOutcome string

const (
	ApplicationEnrollmentCreated         ApplicationEnrollmentOutcome = "created"
	ApplicationEnrollmentAlreadyPending  ApplicationEnrollmentOutcome = "already_pending"
	ApplicationEnrollmentAlreadyApproved ApplicationEnrollmentOutcome = "already_approved"
	ApplicationEnrollmentReopened        ApplicationEnrollmentOutcome = "reopened"
)

type ApplicationEnrollmentResult struct {
	Application string                       `json:"application"`
	Status      string                       `json:"status"`
	Outcome     ApplicationEnrollmentOutcome `json:"-"`
}

func (r *ApplicationEnrollmentResult) CreatedPendingRequest() bool {
	if r == nil {
		return false
	}

	return r.Outcome == ApplicationEnrollmentCreated ||
		r.Outcome == ApplicationEnrollmentReopened
}
