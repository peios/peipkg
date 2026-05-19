package version

import (
	"cmp"
	"fmt"
	"strings"
)

// Operator is a version-constraint relational operator (§2.2.8).
type Operator string

const (
	OpEqual        Operator = "="
	OpGreater      Operator = ">"
	OpGreaterEqual Operator = ">="
	OpLess         Operator = "<"
	OpLessEqual    Operator = "<="
	OpNotEqual     Operator = "!="
)

// expression is one operator-and-version term of a constraint.
type expression struct {
	op      Operator
	operand Version
}

// Constraint is a parsed version constraint (§2.2.8): one or more
// operator-and-version expressions combined with logical AND. The zero
// Constraint imposes no restriction — it matches every version.
type Constraint struct {
	exprs []expression
}

// ParseConstraint parses a constraint string per §2.2.8: comma-separated
// expressions, each an optional operator followed by a version, combined
// with logical AND. A bare version with no operator means `=`.
// Whitespace around operators and commas is ignored.
//
// A constraint operand MAY omit the `-revision` (`>= 3.0`): the operand
// is then matched on epoch and upstream version only.
func ParseConstraint(s string) (Constraint, error) {
	var exprs []expression
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			return Constraint{}, fmt.Errorf(
				"peipkg/version: constraint %q has an empty expression", s)
		}
		e, err := parseExpression(part)
		if err != nil {
			return Constraint{}, fmt.Errorf("peipkg/version: invalid constraint %q: %w", s, err)
		}
		exprs = append(exprs, e)
	}
	return Constraint{exprs: exprs}, nil
}

// parseExpression parses one operator-and-version term.
func parseExpression(part string) (expression, error) {
	op := OpEqual
	operandStr := part
	// Two-character operators are checked before their one-character
	// prefixes so `>=` is not mistaken for `>`.
	switch {
	case strings.HasPrefix(part, ">="):
		op, operandStr = OpGreaterEqual, part[2:]
	case strings.HasPrefix(part, "<="):
		op, operandStr = OpLessEqual, part[2:]
	case strings.HasPrefix(part, "!="):
		op, operandStr = OpNotEqual, part[2:]
	case strings.HasPrefix(part, ">"):
		op, operandStr = OpGreater, part[1:]
	case strings.HasPrefix(part, "<"):
		op, operandStr = OpLess, part[1:]
	case strings.HasPrefix(part, "="):
		op, operandStr = OpEqual, part[1:]
	}
	operand, err := parse(strings.TrimSpace(operandStr), true)
	if err != nil {
		return expression{}, err
	}
	return expression{op: op, operand: operand}, nil
}

// Matches reports whether v satisfies the constraint: every expression
// must hold (logical AND). The zero Constraint matches every version.
func (c Constraint) Matches(v Version) bool {
	for _, e := range c.exprs {
		if !e.matches(v) {
			return false
		}
	}
	return true
}

// matches reports whether v satisfies one expression. When the operand
// omitted its revision, the revision is not part of the comparison.
func (e expression) matches(v Version) bool {
	c := compareEpochUpstream(v, e.operand)
	if c == 0 && e.operand.revision != 0 {
		c = cmp.Compare(v.revision, e.operand.revision)
	}
	switch e.op {
	case OpEqual:
		return c == 0
	case OpGreater:
		return c > 0
	case OpGreaterEqual:
		return c >= 0
	case OpLess:
		return c < 0
	case OpLessEqual:
		return c <= 0
	case OpNotEqual:
		return c != 0
	default:
		return false // unreachable: the operator is validated at parse time
	}
}

// String renders the constraint in a canonical, re-parseable form.
func (c Constraint) String() string {
	if len(c.exprs) == 0 {
		return "any"
	}
	parts := make([]string, len(c.exprs))
	for i, e := range c.exprs {
		parts[i] = string(e.op) + " " + e.operand.String()
	}
	return strings.Join(parts, ", ")
}
