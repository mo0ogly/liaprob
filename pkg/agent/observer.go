package agent

// Observer analyzes task observations and decides if replanning is necessary.
type Observer struct {
	journal *Journal
	memory  *WorkingMemory
}

// NewObserver creates an observer.
func NewObserver(journal *Journal, memory *WorkingMemory) *Observer {
	return &Observer{journal: journal, memory: memory}
}

// Analyze evaluates an observation and returns a decision.
// true = replan necessary, false = continue normally.
func (o *Observer) Analyze(obs Observation, task *ScanTask) bool {
	if !obs.NeedsReplan {
		return false
	}

	o.journal.Log(LevelObserve, "OBSERVATION", task.ID, map[string]interface{}{
		"trigger": string(obs.Trigger),
		"details": obs.Details,
		"host":    obs.Host,
		"port":    obs.Port,
	}, 0)

	switch obs.Trigger {
	case TriggerTooManyHosts:
		// Too many hosts -> sampling recommended
		return true

	case TriggerHostTimeout:
		// All hosts timeout -> check network config
		return true

	case TriggerUnknownBanner:
		// Unknown banner -> add AI identification task
		return obs.NeedsAI

	case TriggerRateLimited:
		// Rate limited -> slow down probes
		return true

	case TriggerUnexpectedService:
		// Unexpected service -> contextual expansion
		return true

	case TriggerPortFiltered:
		// Port filtered -> alternative strategy (SYN, fragments)
		return false // No replan for single filtered port

	default:
		return false
	}
}

// ShouldAddAITask returns true if the observation justifies an additional AI task.
func (o *Observer) ShouldAddAITask(obs Observation) bool {
	return obs.NeedsAI
}
