package middleware

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/o1egl/paseto/v2"
)

// Errors
var (
	errPASETOMissing     = errors.New("missing or malformed paseto Key")
	errPASETOUnsupported = errors.New("unsupported paseto version/purpose")
)

// Config defines the config for PASETO middleware.
type Config struct {

	// Filter defines a function to skip middleware.
	// Optional. Default: nil
	Filter func(*fiber.Ctx) bool

	// SuccessHandler defines a function which is executed for a valid key.
	// Optional. Default: nil
	SuccessHandler fiber.Handler

	// ErrorHandler defines a function which is executed for an invalid key.
	// It may be used to define a custom error.
	// Optional. Default: 401 Invalid or expired key
	ErrorHandler fiber.ErrorHandler

	// Signing key to validate token.
	// Required.
	SigningKey []byte

	// Validators is the list of custom validators.
	// Time validation is enforced.
	Validators []paseto.Validator

	// Context key to store the bearertoken from the token into context.
	// Optional. Default: "token".
	ContextKey string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "param:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default value "Bearer".
	AuthScheme string
}

// Token represents a PASETO JSONToken with its footer.
type Token struct {
	paseto.JSONToken
	Footer string
}

var (
	// DefaultPASETOConfig is the default PASETO auth middleware config.
	DefaultPASETOConfig = Config{
		ContextKey:  "token",
		TokenLookup: "header:" + fiber.HeaderAuthorization,
		AuthScheme:  "Bearer",
		Validators:  []paseto.Validator{},
	}
)

// New ...
func New(config Config) fiber.Handler {

	if len(config.SigningKey) != 32 {
		panic("SigningKey must be 32 bytes length")
	}

	if config.ContextKey == "" {
		config.ContextKey = DefaultPASETOConfig.ContextKey
	}

	if config.Validators == nil {
		config.Validators = DefaultPASETOConfig.Validators
	}

	if config.TokenLookup == "" {
		config.TokenLookup = DefaultPASETOConfig.TokenLookup
	}

	if config.AuthScheme == "" {
		config.AuthScheme = DefaultPASETOConfig.AuthScheme
	}

	// Initialize
	parts := strings.Split(config.TokenLookup, ":")
	extractor := pasetoFromHeader(parts[1], config.AuthScheme)
	switch parts[0] {
	case "query":
		extractor = pasetoFromQuery(parts[1])
	case "param":
		extractor = pasetoFromParam(parts[1])
	case "cookie":
		extractor = pasetoFromCookie(parts[1])
	}

	// Return middleware handler
	return func(c *fiber.Ctx) error {
		if config.Filter != nil && config.Filter(c) {
			return c.Next()
		}

		auth, err := extractor(c)
		if err != nil {
			if config.ErrorHandler != nil {
				return config.ErrorHandler(c, err)
			}
			return err
		}

		// TODO: support v2.public
		if !strings.HasPrefix(auth, "v2.local.") {
			if config.ErrorHandler != nil {
				return config.ErrorHandler(c, errPASETOUnsupported)
			}
			return errPASETOUnsupported
		}

		var token Token
		err = paseto.Decrypt(auth, config.SigningKey, &token.JSONToken, &token.Footer)
		if err == nil {
			err = token.Validate(append(config.Validators, paseto.ValidAt(time.Now()))...)
			if err == nil {
				// Store user information from token into context.
				c.Locals(config.ContextKey, token)
				if config.SuccessHandler != nil {
					config.SuccessHandler(c)
				}
				return c.Next()
			}
		}

		if config.ErrorHandler != nil {
			return config.ErrorHandler(c, err)
		}
		return config.ErrorHandler(c, err)
	}
}

// pasetoFromHeader returns a `pasetoExtractor` that extracts token from the request header.
func pasetoFromHeader(header string, authScheme string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		auth := c.Get(header)
		l := len(authScheme)
		if l == 0 {
			return auth, nil
		}
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", errPASETOMissing
	}
}

// pasetoFromQuery returns a `pasetoExtractor` that extracts token from the query string.
func pasetoFromQuery(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Query(param)
		if token == "" {
			return "", errPASETOMissing
		}
		return token, nil
	}
}

// pasetoFromParam returns a `pasetoExtractor` that extracts token from the url param string.
func pasetoFromParam(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Params(param)
		if token == "" {
			return "", errPASETOMissing
		}
		return token, nil
	}
}

// pasetoFromCookie returns a `pasetoExtractor` that extracts token from the named cookie.
func pasetoFromCookie(name string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Cookies(name)
		if token == "" {
			return "", errPASETOMissing
		}
		return token, nil
	}
}
