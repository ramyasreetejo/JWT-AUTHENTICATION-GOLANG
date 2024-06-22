// package contextkeys defines custom types for context keys
package contextKeys

// Define a custom type for context keys
type ContextKey string

const (
	EmailKey     ContextKey = "email"
	FirstNameKey ContextKey = "first_name"
	LastNameKey  ContextKey = "last_name"
	UserIDKey    ContextKey = "user_id"
	UserTypeKey  ContextKey = "user_type"
)
