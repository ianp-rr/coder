package database

import (
	"github.com/google/uuid"

	"github.com/coder/coder/v2/codersdk"
)

// PrebuildsSystemUserID mirrors codersdk.PrebuildsSystemUserID, parsed
// for use as a uuid.UUID. Both must agree; tests pin the value to the
// codersdk constant so the two cannot drift.
var PrebuildsSystemUserID = uuid.MustParse(codersdk.PrebuildsSystemUserID)

// Values stored in oauth2_provider_apps.client_type.
//
// Aliased from codersdk rather than redeclared. Registration derives the value
// there (OAuth2ClientRegistrationRequest.DetermineClientType) while
// OAuth2ProviderApp.IsPublic reads it back here to decide whether the token
// endpoint validates a client secret at all. A literal that drifted toward
// "public" between the two would silently disable client authentication, and
// nothing would catch it, so the compiler holds the two spellings equal
// instead of a test asserting it after the fact.
const (
	OAuth2ProviderAppClientTypeConfidential = codersdk.OAuth2ClientTypeConfidential
	OAuth2ProviderAppClientTypePublic       = codersdk.OAuth2ClientTypePublic
)
