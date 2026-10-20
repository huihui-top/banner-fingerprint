package fingerprint

import (
	"context"

	"github.com/huihui-top/banner-fingerprint/internal/fingerprint/parsers"
	"github.com/huihui-top/banner-fingerprint/internal/model"
)

type Engine struct {
	rules []compiledRule
}

func (e *Engine) RuleCount() int { return len(e.rules) }

func (e *Engine) Identify(ctx context.Context, input model.Input) (model.Result, error) {
	result := model.Unknown(input.IP, input.Port)
	sources := parsers.Evidence(input.Banner)
	for _, rule := range e.rules {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		for _, value := range sources[rule.Source] {
			version := ""
			if rule.Match.Type == "exact" {
				if value != rule.Match.Pattern {
					continue
				}
			} else {
				match := rule.expression.FindStringSubmatch(value)
				if match == nil {
					continue
				}
				if rule.versionIdx > 0 {
					version = match[rule.versionIdx]
					if version == "" || len(version) > 256 {
						continue
					}
				}
			}
			result.Protocol = rule.Protocol
			result.Product = rule.Product
			result.Version = version
			result.Confidence = rule.Confidence
			for i, pattern := range rule.osPatterns {
				if pattern.MatchString(value) {
					result.OSHint = rule.OSHints[i].Value
					break
				}
			}
			return result, nil
		}
	}
	return result, nil
}
