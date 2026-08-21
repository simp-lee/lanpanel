package application

import "lanpanel/internal/domain"

type (
	EmptyPayload struct{}
	PlanPayload  struct {
		Operation domain.OperationCode   `json:"operation"`
		Target    domain.OperationTarget `json:"target"`
	}
)

type ConfirmationPayload struct {
	PlanID       string `json:"plan_id"`
	Confirmation string `json:"confirmation"`
}

// CoreActions is the complete Management vocabulary. Availability is a
// separate capability and exists only after a complete handler registration.
func CoreActions() []domain.OperationCode {
	return []domain.OperationCode{
		domain.OperationPlan,
		domain.OperationStatus,
		domain.OperationAdminTokenRotate,
		domain.OperationHeadscaleInitialize,
		domain.OperationHeadscaleControlDeploy,
		domain.OperationHeadscaleReissue,
		domain.OperationHeadscaleUserCreate,
		domain.OperationHeadscaleUserList,
		domain.OperationPreauthKeyCreate,
		domain.OperationPreauthKeyList,
		domain.OperationPreauthKeyRevoke,
		domain.OperationDeviceList,
		domain.OperationDeviceExpire,
		domain.OperationConnectorBindingSet,
		domain.OperationConnectorVerify,
		domain.OperationConnectorLogin,
		domain.OperationResourceCreate,
		domain.OperationResourceUpdate,
		domain.OperationPublish,
		domain.OperationUnpublish,
		domain.OperationCloseAll,
		domain.OperationProcessStart,
		domain.OperationProcessStop,
		domain.OperationManagedBasicCreate,
		domain.OperationManagedBasicRotate,
		domain.OperationManagedBasicDelete,
		domain.OperationStaticRootRegister,
		domain.OperationExternalHTPasswdRegister,
		domain.OperationResourceDelete,
		domain.OperationDiagnostics,
		domain.OperationConfigurationExport,
		domain.OperationJobList,
		domain.OperationJobDetail,
	}
}
func Route(operation domain.OperationCode) string { return "/api/actions/" + string(operation) }
