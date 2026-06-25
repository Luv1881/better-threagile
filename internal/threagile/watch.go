package threagile

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"github.com/threagile/threagile/pkg/model"
	"github.com/threagile/threagile/pkg/prioritize"
	"github.com/threagile/threagile/pkg/risks"
	"github.com/threagile/threagile/pkg/score"
)

func (what *Threagile) initWatch() *Threagile {
	watch := &cobra.Command{
		Use:   WatchCommand,
		Short: "Watch the model and show live score + top findings on every save",
		RunE: func(cmd *cobra.Command, args []string) error {
			what.processArgs(cmd, args)

			modelFile := what.config.GetInputFile()
			watchDir := filepath.Dir(modelFile)

			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				return fmt.Errorf("failed to create file watcher: %w", err)
			}
			defer func() { _ = watcher.Close() }()

			if err := watcher.Add(watchDir); err != nil {
				return fmt.Errorf("failed to watch directory %q: %w", watchDir, err)
			}

			cmd.Printf("Watching %s for changes (Ctrl+C to stop)...\n\n", watchDir)

			// Run once immediately
			runAnalysis(what, cmd)

			debounce := time.NewTimer(0)
			<-debounce.C // drain initial fire

			for {
				select {
				case event, ok := <-watcher.Events:
					if !ok {
						return nil
					}
					if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
						if filepath.Ext(event.Name) == ".yaml" || filepath.Ext(event.Name) == ".yml" {
							debounce.Reset(300 * time.Millisecond)
						}
					}

				case err, ok := <-watcher.Errors:
					if !ok {
						return nil
					}
					cmd.Printf("Watch error: %v\n", err)

				case <-debounce.C:
					cmd.Printf("\n[%s] Change detected — re-analyzing...\n", time.Now().Format("15:04:05"))
					runAnalysis(what, cmd)
				}
			}
		},
	}

	what.rootCmd.AddCommand(watch)
	return what
}

func runAnalysis(what *Threagile, cmd *cobra.Command) {
	progressReporter := DefaultProgressReporter{Verbose: false}
	builtinRules := risks.GetBuiltInRiskRules()

	result, err := model.ReadAndAnalyzeModel(what.config, builtinRules, progressReporter)
	if err != nil {
		cmd.Printf("Analysis failed: %v\n", err)
		return
	}

	totalRisks := 0
	for _, v := range result.ParsedModel.GeneratedRisksByCategory {
		totalRisks += len(v)
	}

	// Live, actionable feedback: the health score plus the top few things to fix,
	// so the developer sees the impact of each save immediately.
	sc := score.Compute(result.ParsedModel)
	cmd.Printf("✓ %d risks · score %d/100 (grade %s) · completeness %.0f%% posture %.0f%%\n",
		totalRisks, sc.Overall, sc.Grade, sc.Completeness*100, sc.Posture*100)
	for _, n := range sc.Notes {
		cmd.Printf("  ! %s\n", n)
	}

	pr := prioritize.Analyze(result.ParsedModel)
	if top := pr.Top(3); len(top) > 0 {
		cmd.Printf("  Fix first (of %d at risk):\n", pr.TotalAtRisk)
		for i, it := range top {
			cmd.Printf("    %d. [%d] %s — %s\n", i+1, it.Score, it.Severity, prioritizeTitle(it.Title))
		}
	}
}

// prioritizeTitle trims an over-long HTML-ish risk title for the watch summary.
func prioritizeTitle(title string) string {
	t := prioritize.Plain(title)
	if len(t) > 80 {
		return t[:77] + "..."
	}
	return t
}
