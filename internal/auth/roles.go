package auth

// Application roles.
const (
	RoleMember = "member" // manages their own sites, forms and submissions
	RoleAdmin  = "admin"  // sees all sites and manages accounts
)

func IsAdmin(role string) bool {
	return role == RoleAdmin
}

func ValidRole(role string) bool {
	switch role {
	case RoleMember, RoleAdmin:
		return true
	}
	return false
}
