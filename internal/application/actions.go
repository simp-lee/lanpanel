package application

import "lanpanel/internal/domain"

type EmptyPayload struct{}
type PlanPayload struct {
	Operation domain.OperationCode   `json:"operation"`
	Target    domain.OperationTarget `json:"target"`
}
type ConfirmationPayload struct {
	PlanID       string `json:"plan_id"`
	Confirmation string `json:"confirmation"`
}

// CoreActions is the complete Management vocabulary. Availability is a
// separate capability and exists only after a complete handler registration.
func CoreActions() []domain.OperationCode {
	return []domain.OperationCode{
		domain.OperationInstanceConfigCreate, domain.OperationInstanceConfigUpdate, domain.OperationValidate, domain.OperationPlan, domain.OperationDeploy, domain.OperationStatus, domain.OperationDiagnostics, domain.OperationConfigurationExport, domain.OperationAdminTokenRotate, domain.OperationHeadscaleReissue, domain.OperationDependencyUpload, domain.OperationDependencyImport, domain.OperationMaintenance, domain.OperationBackupEnter, domain.OperationBackupPreparingAbort, domain.OperationBackupExit, domain.OperationRestoreEvidenceImport, domain.OperationRestoreCutover, domain.OperationConnectorVerify, domain.OperationConnectorAuthKeyImport, domain.OperationConnectorAuthKeyAdopt, domain.OperationConnectorAuthKeyDiscard, domain.OperationConnectorLogin, domain.OperationConnectorDisconnect, domain.OperationConnectorRebind, domain.OperationResourceCreate, domain.OperationResourceUpdate, domain.OperationResourceDelete, domain.OperationPublish, domain.OperationUnpublish, domain.OperationCloseAll, domain.OperationProcessStart, domain.OperationProcessStop, domain.OperationUnpublishAndStop, domain.OperationHeadscaleUserCreate, domain.OperationHeadscaleUserList, domain.OperationPreauthKeyCreate, domain.OperationPreauthKeyList, domain.OperationPreauthKeyRevoke, domain.OperationDeviceList, domain.OperationDeviceExpire, domain.OperationManagedBasicCreate, domain.OperationManagedBasicRotate, domain.OperationManagedBasicDelete, domain.OperationStaticRootRegister, domain.OperationExternalHTPasswdRegister, domain.OperationEdgeOneDiagnostics, domain.OperationEdgeOneRefresh, domain.OperationJobList, domain.OperationJobDetail, domain.OperationSessionLogout,
	}
}
func Route(operation domain.OperationCode) string { return "/api/actions/" + string(operation) }
