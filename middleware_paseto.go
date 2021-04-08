package middleware

import (
	"errors"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/o1egl/paseto/v2"
)

var (
	errPASETOMissing     = errors.New("missing or malformed paseto Key")
	errPASETOUnsupported = errors.New("unsupported paseto version/purpose")
)

type Config struct {

	// PASETOConfig defines the config for PASETO middleware.
	// Filter defines a function to skip middleware.
	Filter func(*fiber.Ctx) bool

	// SuccessHandler defines a function which is executed for a valid token.
	SuccessHandler fiber.Handler

	// ErrorHandler defines a function which is executed for an invalid token.
	// It may be used to define a custom PASETO error.
	ErrorHandler fiber.ErrorHandler

	// ErrorHandlerWithContext is almost identical to ErrorHandler, but it's passed the current context.
	ErrorHandlerWithContext func(error, *fiber.Ctx) error

	// Signing key to validate token.
	// Required.
	SigningKey []byte

	// Validators is the list of custom validators.
	// Time validation is enforced.
	Validators []paseto.Validator

	// Context key to store user information from the token into context.
	// Optional. Default value "user".
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

// New ...
func New(config ...Config) fiber.Handler {
	// Init config
	var cfg Config

	if len(config) > 0 {
		cfg = config[0]
	}
	if cfg.SuccessHandler == nil {
		cfg.SuccessHandler = func(c *fiber.Ctx) error {
			return c.Next()
		}
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = func(c *fiber.Ctx, err error) error {
			if err == errPASETOMissing {
				return c.Status(fiber.StatusBadRequest).SendString(err.Error())
			}
			return c.Status(fiber.StatusUnauthorized).SendString("invalid or expired paseto")

		}
	}

	if len(cfg.SigningKey) != 32 {
		panic("SigningKey must be 32 bytes length")
	}

	if cfg.TokenLookup == "" {
		cfg.TokenLookup = "header:" + fiber.HeaderAuthorization

		if cfg.AuthScheme == "" {
			cfg.AuthScheme = "Bearer"
		}
	}

	if cfg.Validators == nil {
		cfg.Validators = []paseto.Validator{}
	}

	if cfg.ContextKey == "" {
		cfg.ContextKey = "token"
	}

	// Initialize
	parts := strings.Split(cfg.TokenLookup, ":")
	extractor := pasetoFromHeader(parts[1], cfg.AuthScheme)
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
		if cfg.Filter != nil && cfg.Filter(c) {
			return c.Next()
		}

		auth, err := extractor(c)
		if err != nil {
			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c, err)
			}

			if cfg.ErrorHandlerWithContext != nil {
				return cfg.ErrorHandlerWithContext(err, c)
			}
			return err
		}

		// TODO: support v2.public
		if !strings.HasPrefix(auth, "v2.local.") {
			if cfg.ErrorHandler != nil {
				return cfg.ErrorHandler(c, errPASETOUnsupported)
			}
			// Status(fiber.StatusBadRequest).SendString("Missing or malformed PASETO")
			if cfg.ErrorHandlerWithContext != nil {
				return cfg.ErrorHandlerWithContext(errPASETOUnsupported, c)
			}
			return errPASETOUnsupported
		}

		var token Token
		err = paseto.Decrypt(auth, cfg.SigningKey, &token.JSONToken, &token.Footer)
		if err == nil {
			err = token.Validate(append(cfg.Validators, paseto.ValidAt(time.Now()))...)
			if err == nil {
				// Store user information from token into context.
				c.Locals(cfg.ContextKey, token)
				if cfg.SuccessHandler != nil {
					cfg.SuccessHandler(c)
				}
				return cfg.SuccessHandler(c)
			}
		}

		if cfg.ErrorHandler != nil {
			return cfg.ErrorHandler(c, err)
		}
		if cfg.ErrorHandlerWithContext != nil {
			return cfg.ErrorHandlerWithContext(err, c)
		}
		return cfg.ErrorHandler(c, err)
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
