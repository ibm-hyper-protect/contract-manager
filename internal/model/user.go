package model

// PersonaRole represents the role a user can have in the system.
type PersonaRole string

const (
	RoleSolutionProvider PersonaRole = "SOLUTION_PROVIDER"
	RoleDataOwner        PersonaRole = "DATA_OWNER"
	RoleAuditor          PersonaRole = "AUDITOR"
	RoleEnvOperator      PersonaRole = "ENV_OPERATOR"
	RoleAdmin            PersonaRole = "ADMIN"
	RoleViewer           PersonaRole = "VIEWER"
)

// String returns the string representation of the role.
func (r PersonaRole) String() string {
	return string(r)
}

// IsValid checks if the role is a recognized persona role.
func (r PersonaRole) IsValid() bool {
	switch r {
	case RoleSolutionProvider, RoleDataOwner, RoleAuditor,
		RoleEnvOperator, RoleAdmin, RoleViewer:
		return true
	}
	return false
}

// RequiredRoleForTransition maps each build status transition to the persona role
// that is allowed to perform it (v2 workflow).
var RequiredRoleForTransition = map[BuildStatus]PersonaRole{
	StatusSigningKeyRegistered:     RoleAuditor,
	StatusWorkloadSubmitted:        RoleSolutionProvider,
	StatusEnvironmentStaged:        RoleDataOwner,
	StatusAttestationKeyRegistered: RoleAuditor,
	StatusFinalized:                RoleAuditor,
	StatusContractDownloaded:       RoleEnvOperator,
}
