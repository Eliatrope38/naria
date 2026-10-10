package auth

// Account roles.
const (
	RoleAdmin    = "admin"      // platform administrator: manages organisations, sees no site or submission
	RoleOrgAdmin = "admin_orga" // administers one organisation: its sites, forms, submissions and users
	RoleUser     = "user"       // manages the sites it owns, and reads those an organisation shared with it
)
