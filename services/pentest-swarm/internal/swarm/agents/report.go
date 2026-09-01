package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	reportpkg "github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/bounty"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/agent/report/roi"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/pipeline"
	"github.com/Armur-Ai/Pentest-Swarm-AI/internal/swarm/blackboard"
	"github.com/google/uuid"
)

// ReportAgent wakes on CAMPAIGN_COMPLETE, queries the blackboard for
// everything the swarm discovered, reconstructs the classical
// Campaign / Findings / Plan / Results shape, and hands it to the
// existing report agent for rendering.
type ReportAgent struct {
	reportAgent      *reportpkg.ReportAgent
	renderer         *reportpkg.Renderer
	campaign         pipeline.Campaign
	outputDir        string
	format           string
	publishThreshold float64 // findings below this pheromone are excluded from the report
	onRendered       func(paths map[string]string)
	// spendSnapshot returns the current LLM dollar spend, or 0 if no
	// metered provider is wired. Optional — when nil, the ROI footer
	// is omitted from the report.
	spendSnapshot func() float64
	// programStats is the per-program bounty stats used to refine the
	// ROI estimate. Optional — nil falls back to industry-average
	// public-market numbers in `internal/agent/report/bounty`.
	programStats *bounty.ProgramStats
}

// NewReportAgent wires the existing report agent into the swarm.
// publishThreshold gates which findings appear in the report:
//
//	0.5 (default) — 'bugbounty' mode: verified PoCs only.
//	                ConfirmationAgent's superseded findings (pheromone
//	                0.1) are automatically excluded.
//	0.1 ('aggressive') — include everything including suspected-but-
//	                not-reproduced findings (with a banner in the report).
func NewReportAgent(inner *reportpkg.ReportAgent, renderer *reportpkg.Renderer, campaign pipeline.Campaign, outputDir, format string, publishThreshold float64, onRendered func(map[string]string)) *ReportAgent {
	if outputDir == "" {
		outputDir = "./reports"
	}
	if format == "" {
		format = "md"
	}
	if publishThreshold <= 0 {
		publishThreshold = 0.5
	}
	return &ReportAgent{
		reportAgent:      inner,
		renderer:         renderer,
		campaign:         campaign,
		outputDir:        outputDir,
		format:           format,
		publishThreshold: publishThreshold,
		onRendered:       onRendered,
	}
}

// WithROI attaches a spend-snapshot closure and (optionally) per-program
// bounty stats so the agent can render an ROI footer at the bottom of
// the campaign report. Closure form means the snapshot stays fresh —
// we read it at render time, not at agent construction time.
func (a *ReportAgent) WithROI(spend func() float64, stats *bounty.ProgramStats) *ReportAgent {
	a.spendSnapshot = spend
	a.programStats = stats
	return a
}

// Name implements swarm.Agent.
func (a *ReportAgent) Name() string { return "report" }

// Trigger implements swarm.Agent.
func (a *ReportAgent) Trigger() blackboard.Predicate {
	return blackboard.Predicate{Types: []blackboard.FindingType{blackboard.TypeCampaignComplete}}
}

// MaxConcurrency implements swarm.Agent — exactly one report per campaign.
func (a *ReportAgent) MaxConcurrency() int { return 1 }

// Handle queries the board, generates, renders, and writes the report.
func (a *ReportAgent) Handle(ctx context.Context, f blackboard.Finding, board blackboard.Board) error {
	// Reconstruct findings. publishThreshold excludes low-pheromone findings
	// (those superseded by the ConfirmationAgent, or agent-error noise).
	matches, _ := board.Query(ctx, blackboard.Predicate{
		Types:        []blackboard.FindingType{blackboard.TypeCVEMatch, blackboard.TypeMisconfig},
		MinPheromone: a.publishThreshold,
		Limit:        500,
	})
	findings := make([]pipeline.ClassifiedFinding, 0, len(matches))
	for _, m := range matches {
		var cf pipeline.ClassifiedFinding
		if err := json.Unmarshal(m.Data, &cf); err == nil {
			findings = append(findings, cf)
		}
	}

	// Reconstruct plan
	var plan *pipeline.AttackPlan
	chains, _ := board.Query(ctx, blackboard.Predicate{
		Types: []blackboard.FindingType{blackboard.TypeExploitChain},
		Limit: 100,
	})
	if len(chains) > 0 {
		plan = &pipeline.AttackPlan{
			ID:         uuid.New(),
			CampaignID: a.campaign.ID,
			CreatedAt:  a.campaign.CreatedAt,
		}
		for _, c := range chains {
			var p pipeline.AttackPath
			if err := json.Unmarshal(c.Data, &p); err == nil {
				plan.Paths = append(plan.Paths, p)
			}
		}
	}

	// Reconstruct execution results
	resultFinds, _ := board.Query(ctx, blackboard.Predicate{
		Types: []blackboard.FindingType{blackboard.TypeExploitResult},
		Limit: 500,
	})
	results := make([]pipeline.ExecutionResult, 0, len(resultFinds))
	for _, r := range resultFinds {
		var wrapped struct {
			Result pipeline.ExecutionResult `json:"result"`
		}
		if err := json.Unmarshal(r.Data, &wrapped); err == nil {
			results = append(results, wrapped.Result)
		}
	}

	rep, err := a.reportAgent.Generate(ctx, a.campaign, findings, plan, results)
	if err != nil {
		return fmt.Errorf("generate report: %w", err)
	}

	// Phase 4.5.7: ROI footer. Only renders when a metered provider was
	// wired into the swarm — otherwise we'd be dividing by an unknown
	// spend and the verdict would be meaningless.
	if a.spendSnapshot != nil {
		rep.ROIFooter = roi.Calculate(a.spendSnapshot(), findings, a.programStats).Footer()
	}

	if err := os.MkdirAll(a.outputDir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	base := filepath.Join(a.outputDir, fmt.Sprintf("%s-%s", a.campaign.Name, a.campaign.ID.String()[:8]))
	rendered := map[string]string{}

	want := func(kind string) bool {
		return a.format == "all" || a.format == kind
	}
	if a.format == "" || want("md") {
		if b, err := a.renderer.ToMarkdown(rep); err == nil {
			p := base + ".md"
			_ = os.WriteFile(p, b, 0o644)
			rendered["md"] = p
		}
	}
	if want("html") {
		if b, err := a.renderer.ToHTML(rep); err == nil {
			p := base + ".html"
			_ = os.WriteFile(p, b, 0o644)
			rendered["html"] = p
		}
	}
	if want("json") {
		if b, err := a.renderer.ToJSON(rep); err == nil {
			p := base + ".json"
			_ = os.WriteFile(p, b, 0o644)
			rendered["json"] = p
		}
	}
	if want("sarif") {
		if b, err := a.renderer.ToSARIF(rep); err == nil {
			p := base + ".sarif"
			_ = os.WriteFile(p, b, 0o644)
			rendered["sarif"] = p
		}
	}

	if a.onRendered != nil {
		a.onRendered(rendered)
	}
	return nil
}
