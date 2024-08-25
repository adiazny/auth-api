package main

import (
	"context"
	_ "embed"
	"errors"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/open-policy-agent/opa/rego"
)

// These the current set of rules we have for auth.
const (
	RuleAuthenticate = "auth"
)

// Package name of our rego code.
const (
	opaPackage string = "diaz.rego"
)

// Core OPA policies.
var (
	//go:embed authentication.rego
	regoAuthentication string
)

func main() {
	app := fiber.New(fiber.Config{
		ServerHeader: "Fiber",
		AppName:      "Auth API v0.1.0",
	})

	app.Get("/", auth)

	err := app.Listen(":3000")
	if err != nil {
		fmt.Printf("error: %v", err)
	}
}

func auth(c *fiber.Ctx) error {

	// input := map[string]any{
	// 	"Is_Admin": true,
	// 	"Username": "Alan",
	// 	"UID":      12345,
	// }

	user := struct {
		IsAdmin  bool   `json:"Is_Admin"`
		Username string `json:"username"`
		UID      int    `json:"uid"`
	}{
		IsAdmin:  true,
		Username: "john_doe",
		UID:      12345,
	}

	err := opaPolicyEvaluation(c.UserContext(), regoAuthentication, RuleAuthenticate, user)
	if err != nil {
		c.SendString("jwt not valid")
		return err
	}

	c.SendString("Auth-API")

	return nil
}

// rego policy
// go rego code to evaluate input against policy
// return valid or invalid

func opaPolicyEvaluation(ctx context.Context, regoScript string, rule string, input any) error {
	query := fmt.Sprintf("x = data.%s.%s", opaPackage, rule)

	q, err := rego.New(
		rego.Query(query),
		rego.Module("policy.rego", regoScript),
	).PrepareForEval(ctx)
	if err != nil {
		return err
	}

	results, err := q.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return fmt.Errorf("query: %w", err)
	}

	if len(results) == 0 {
		return errors.New("no results")
	}

	result, ok := results[0].Bindings["x"].(bool)
	if !ok || !result {
		return fmt.Errorf("bindings results[%v] ok[%v]", result, ok)
	}

	return nil
}
