//! Staged rollout (H-HA-02, ADR-0031): a published revision goes to one canary first and to
//! the rest after a soak time; a refusal halts it. The state lives in
//! `<data>/control/rollout.json` so a restart of the control plane keeps a halt.
//!
//! The rules, all decided here and tested without processes:
//!
//! - **Which revision an instance is given** ([`Rollout::target`]): the revision being rolled
//!   out once the rollout is complete; while it runs, the canary gets it and every other
//!   instance gets the *stable* revision (the last one whose rollout completed); after a halt,
//!   the instances that were already given it keep it and the rest stay on the stable one.
//! - **The canary** is `control.rollout.canary` when that instance is online, else the first
//!   online instance by name. With no instance online at publication the first one that comes
//!   online is chosen. A canary that does not report within `canary_timeout` halts the rollout.
//! - **Immediate rollouts**: `mode: all`, the first revision of a cluster (nothing to stay on)
//!   and rollbacks (their document already ran) go to every instance at once.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use rdock_cluster::protocol::Verdict;
use rdock_model::cluster::RolloutMode;
use serde::{Deserialize, Serialize};

use crate::Error;

/// Where a rollout stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// No revision was published yet.
    None,
    /// The canary has been given the revision (or none is online yet) and has not
    /// acknowledged it.
    Canary,
    /// The canary acknowledged the revision; the rest follow when the soak time is over.
    Soaking,
    /// Every instance is given the revision.
    Complete,
    /// A refusal or a silent canary stopped the rollout: instances not given the revision yet
    /// stay on the stable one until an operator resumes or abandons it.
    Halted,
}

impl Phase {
    /// The word used in the API and the CLI.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Canary => "canary",
            Self::Soaking => "soaking",
            Self::Complete => "complete",
            Self::Halted => "halted",
        }
    }
}

/// Why a rollout halted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Halt {
    /// When (Unix seconds).
    pub at: i64,
    /// The instance that refused, or the silent canary.
    pub instance: Option<String>,
    /// Why, in words.
    pub reason: String,
}

/// How a past revision's rollout ended, kept for the revision list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Outcome {
    /// `complete`, `halted`, `abandoned` or `superseded`.
    pub state: String,
    /// Why or by whom, in words.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// When (Unix seconds).
    pub at: i64,
}

/// What the control plane should record after a change (logs and the audit log).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The canary was chosen.
    CanaryChosen {
        /// The revision.
        revision: u64,
        /// The canary.
        canary: String,
        /// The configured canary was not online.
        instead_of: Option<String>,
    },
    /// The canary acknowledged; the soak time runs.
    Soaking {
        /// The revision.
        revision: u64,
    },
    /// Every instance is given the revision.
    Completed {
        /// The revision.
        revision: u64,
    },
    /// The rollout halted.
    Halted {
        /// The revision.
        revision: u64,
        /// Why.
        halt: Halt,
    },
}

/// The rollout state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The revision being rolled out (`0` before the first publication).
    pub revision: u64,
    /// The revision every instance may take meanwhile: the last one whose rollout completed.
    pub stable: u64,
    /// The mode it runs in (`all` for immediate rollouts).
    pub mode: RolloutMode,
    /// Where it stands.
    pub phase: Phase,
    /// The canary, once chosen.
    #[serde(default)]
    pub canary: Option<String>,
    /// When it started (Unix seconds).
    pub started_at: i64,
    /// When the canary was chosen (Unix seconds).
    #[serde(default)]
    pub canary_since: Option<i64>,
    /// When the canary acknowledged (Unix seconds).
    #[serde(default)]
    pub canary_acked_at: Option<i64>,
    /// When the rest were given the revision (Unix seconds).
    #[serde(default)]
    pub completed_at: Option<i64>,
    /// Instances given the revision.
    #[serde(default)]
    pub offered: BTreeSet<String>,
    /// Why it halted.
    #[serde(default)]
    pub halt: Option<Halt>,
    /// Who resumed it, if anyone did.
    #[serde(default)]
    pub resumed_by: Option<String>,
    /// How earlier rollouts ended, by revision (the newest 100).
    #[serde(default)]
    pub outcomes: BTreeMap<u64, Outcome>,
}

impl Default for State {
    fn default() -> Self {
        Self {
            revision: 0,
            stable: 0,
            mode: RolloutMode::Canary,
            phase: Phase::None,
            canary: None,
            started_at: 0,
            canary_since: None,
            canary_acked_at: None,
            completed_at: None,
            offered: BTreeSet::new(),
            halt: None,
            resumed_by: None,
            outcomes: BTreeMap::new(),
        }
    }
}

/// The rollout settings and state, with the file it is kept in.
#[derive(Debug)]
pub struct Rollout {
    path: PathBuf,
    settings: rdock_model::cluster::Rollout,
    state: State,
}

/// Why an operator action on a rollout was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The rollout is in a phase where the action means nothing (`409`).
    Conflict(String),
}

const KEPT_OUTCOMES: usize = 100;

impl Rollout {
    /// Loads `<dir>/rollout.json`. `latest` is the newest published revision: a control plane
    /// of step 5 (no rollout file) with revisions treats the newest as complete.
    pub fn load(
        dir: &std::path::Path,
        settings: rdock_model::cluster::Rollout,
        latest: u64,
    ) -> Result<Self, Error> {
        let path = dir.join("rollout.json");
        let state = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| Error::State(format!("{}: {e}", path.display())))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => State {
                revision: latest,
                stable: latest,
                mode: RolloutMode::All,
                phase: if latest == 0 {
                    Phase::None
                } else {
                    Phase::Complete
                },
                ..State::default()
            },
            Err(e) => return Err(Error::State(format!("{}: {e}", path.display()))),
        };
        Ok(Self {
            path,
            settings,
            state,
        })
    }

    /// Writes the state.
    pub fn save(&self) -> Result<(), Error> {
        let json =
            serde_json::to_vec_pretty(&self.state).map_err(|e| Error::State(e.to_string()))?;
        rdock_cluster::dir::write_private(&self.path, &json)
            .map_err(|e| Error::State(format!("{}: {e}", self.path.display())))
    }

    /// The state.
    #[must_use]
    pub fn state(&self) -> &State {
        &self.state
    }

    /// The settings.
    #[must_use]
    pub fn settings(&self) -> &rdock_model::cluster::Rollout {
        &self.settings
    }

    fn outcome(&mut self, revision: u64, state: &str, reason: Option<String>, at: i64) {
        if revision == 0 {
            return;
        }
        self.state.outcomes.insert(
            revision,
            Outcome {
                state: state.to_owned(),
                reason,
                at,
            },
        );
        while self.state.outcomes.len() > KEPT_OUTCOMES {
            self.state.outcomes.pop_first();
        }
    }

    /// Starts rolling out `revision`. `immediate` (a rollback) skips the canary. `online` are
    /// the online, unrevoked instances by name.
    pub fn start(
        &mut self,
        revision: u64,
        immediate: bool,
        online: &[String],
        now: i64,
    ) -> Vec<Event> {
        let previous = std::mem::take(&mut self.state);
        let stable = if previous.phase == Phase::Complete {
            previous.revision
        } else {
            previous.stable
        };
        self.state.outcomes = previous.outcomes;
        if previous.revision != 0 && previous.phase != Phase::Complete {
            self.outcome(
                previous.revision,
                "superseded",
                Some(format!("revision {revision} was published")),
                now,
            );
        }
        let immediate = immediate || stable == 0 || self.settings.mode == RolloutMode::All;
        self.state.revision = revision;
        self.state.stable = stable;
        self.state.started_at = now;
        if immediate {
            self.state.mode = RolloutMode::All;
            self.state.phase = Phase::Complete;
            self.state.completed_at = Some(now);
            self.outcome(revision, "complete", None, now);
            return vec![Event::Completed { revision }];
        }
        self.state.mode = RolloutMode::Canary;
        self.state.phase = Phase::Canary;
        self.choose_canary(online, now).into_iter().collect()
    }

    fn choose_canary(&mut self, online: &[String], now: i64) -> Option<Event> {
        let wanted = self.settings.canary.clone();
        let chosen = match &wanted {
            Some(name) if online.contains(name) => Some(name.clone()),
            _ => online.iter().min().cloned(),
        }?;
        self.state.canary = Some(chosen.clone());
        self.state.canary_since = Some(now);
        Some(Event::CanaryChosen {
            revision: self.state.revision,
            instead_of: wanted.filter(|w| *w != chosen),
            canary: chosen,
        })
    }

    /// The revision `instance` is given now.
    #[must_use]
    pub fn target(&self, instance: &str) -> u64 {
        let s = &self.state;
        match s.phase {
            Phase::None | Phase::Complete => s.revision,
            _ if s.stable == 0 => s.revision,
            Phase::Canary | Phase::Soaking => {
                if s.canary.as_deref() == Some(instance) {
                    s.revision
                } else {
                    s.stable
                }
            }
            Phase::Halted => {
                if s.offered.contains(instance) {
                    s.revision
                } else {
                    s.stable
                }
            }
        }
    }

    /// Records that `instance` was given `revision`; `true` when that changed the state.
    pub fn offered(&mut self, instance: &str, revision: u64) -> bool {
        revision == self.state.revision
            && revision != 0
            && self.state.offered.insert(instance.to_owned())
    }

    /// Takes an instance's report into account.
    pub fn report(
        &mut self,
        instance: &str,
        revision: u64,
        verdict: Verdict,
        reason: Option<&str>,
        now: i64,
    ) -> Vec<Event> {
        if revision != self.state.revision || revision == 0 {
            return Vec::new();
        }
        match (verdict, self.state.phase) {
            (Verdict::Nack, Phase::Canary | Phase::Soaking) => {
                // Instances already given the revision (only the canary here) keep it.
                let halt = Halt {
                    at: now,
                    instance: Some(instance.to_owned()),
                    reason: format!(
                        "{instance} refused revision {revision}{}",
                        reason.map(|r| format!(": {r}")).unwrap_or_default()
                    ),
                };
                self.halt(halt)
            }
            (Verdict::Ack, Phase::Canary) if self.state.canary.as_deref() == Some(instance) => {
                self.state.canary_acked_at = Some(now);
                self.state.phase = Phase::Soaking;
                let mut events = vec![Event::Soaking { revision }];
                events.extend(self.tick(&[], now));
                events
            }
            _ => Vec::new(),
        }
    }

    fn halt(&mut self, halt: Halt) -> Vec<Event> {
        self.state.phase = Phase::Halted;
        self.state.halt = Some(halt.clone());
        self.outcome(
            self.state.revision,
            "halted",
            Some(halt.reason.clone()),
            halt.at,
        );
        vec![Event::Halted {
            revision: self.state.revision,
            halt,
        }]
    }

    fn complete(&mut self, now: i64) -> Vec<Event> {
        self.state.phase = Phase::Complete;
        self.state.completed_at = Some(now);
        self.state.stable = self.state.revision;
        self.outcome(self.state.revision, "complete", None, now);
        vec![Event::Completed {
            revision: self.state.revision,
        }]
    }

    /// Moves the rollout on with time: chooses a canary once one is online, halts on a silent
    /// canary, completes after the soak time.
    pub fn tick(&mut self, online: &[String], now: i64) -> Vec<Event> {
        match self.state.phase {
            Phase::Canary => {
                let Some(since) = self.state.canary_since else {
                    return self.choose_canary(online, now).into_iter().collect();
                };
                let timeout =
                    i64::try_from(self.settings.canary_timeout.as_std().as_secs()).unwrap_or(120);
                if now - since >= timeout {
                    let canary = self.state.canary.clone().unwrap_or_default();
                    let halt = Halt {
                        at: now,
                        instance: Some(canary.clone()),
                        reason: format!(
                            "the canary {canary} did not report on revision {} within {}",
                            self.state.revision, self.settings.canary_timeout
                        ),
                    };
                    return self.halt(halt);
                }
                Vec::new()
            }
            Phase::Soaking => {
                let soak = i64::try_from(self.settings.soak.as_std().as_secs()).unwrap_or(60);
                if self
                    .state
                    .canary_acked_at
                    .is_some_and(|at| now - at >= soak)
                {
                    self.complete(now)
                } else {
                    Vec::new()
                }
            }
            Phase::None | Phase::Complete | Phase::Halted => Vec::new(),
        }
    }

    /// An operator lets a halted (or still soaking) rollout go on: every instance is given the
    /// revision now.
    pub fn resume(&mut self, by: &str, now: i64) -> Result<Vec<Event>, Refusal> {
        match self.state.phase {
            Phase::Halted | Phase::Canary | Phase::Soaking => {
                self.state.resumed_by = Some(by.to_owned());
                self.state.halt = None;
                Ok(self.complete(now))
            }
            Phase::None | Phase::Complete => Err(Refusal::Conflict(format!(
                "the rollout of revision {} is {}; there is nothing to resume",
                self.state.revision,
                self.state.phase.as_str()
            ))),
        }
    }

    /// Checks that the rollout can be abandoned and returns the stable revision to publish
    /// again; the caller publishes it as a rollback, which starts an immediate rollout.
    pub fn abandon_target(&self) -> Result<u64, Refusal> {
        match self.state.phase {
            Phase::Halted | Phase::Canary | Phase::Soaking if self.state.stable != 0 => {
                Ok(self.state.stable)
            }
            Phase::Halted | Phase::Canary | Phase::Soaking => Err(Refusal::Conflict(
                "there is no earlier complete revision to return to".to_owned(),
            )),
            Phase::None | Phase::Complete => Err(Refusal::Conflict(format!(
                "the rollout of revision {} is {}; there is nothing to abandon",
                self.state.revision,
                self.state.phase.as_str()
            ))),
        }
    }

    /// Marks the current revision abandoned (before the rollback is published).
    pub fn abandoned(&mut self, by: &str, now: i64) {
        let revision = self.state.revision;
        self.outcome(
            revision,
            "abandoned",
            Some(format!("abandoned by {by}")),
            now,
        );
        // `start` must not overwrite the outcome with "superseded".
        self.state.phase = Phase::Complete;
        self.state.revision = self.state.stable;
    }

    /// The JSON the API shows.
    #[must_use]
    pub fn view(&self) -> serde_json::Value {
        let s = &self.state;
        let soak_ends = s.canary_acked_at.map(|at| {
            crate::rfc3339(at + i64::try_from(self.settings.soak.as_std().as_secs()).unwrap_or(0))
        });
        serde_json::json!({
            "revision": s.revision,
            "stable": s.stable,
            "mode": match s.mode { RolloutMode::Canary => "canary", RolloutMode::All => "all" },
            "phase": s.phase.as_str(),
            "canary": s.canary,
            "started_at": (s.started_at > 0).then(|| crate::rfc3339(s.started_at)),
            "canary_acked_at": s.canary_acked_at.map(crate::rfc3339),
            "soak_ends_at": if s.phase == Phase::Soaking { soak_ends } else { None },
            "completed_at": s.completed_at.map(crate::rfc3339),
            "offered": s.offered,
            "halt": s.halt.as_ref().map(|h| serde_json::json!({
                "at": crate::rfc3339(h.at),
                "instance": h.instance,
                "reason": h.reason,
            })),
            "resumed_by": s.resumed_by,
            "settings": {
                "mode": match self.settings.mode { RolloutMode::Canary => "canary", RolloutMode::All => "all" },
                "canary": self.settings.canary,
                "soak_seconds": self.settings.soak.as_std().as_secs(),
                "canary_timeout_seconds": self.settings.canary_timeout.as_std().as_secs(),
            },
        })
    }

    /// How the rollout of `revision` ended or stands, for the revision list.
    #[must_use]
    pub fn outcome_of(&self, revision: u64) -> Option<serde_json::Value> {
        if revision == self.state.revision && self.state.phase != Phase::Complete {
            return Some(serde_json::json!({
                "state": self.state.phase.as_str(),
                "reason": self.state.halt.as_ref().map(|h| h.reason.clone()),
            }));
        }
        self.state.outcomes.get(&revision).map(|o| {
            serde_json::json!({ "state": o.state, "reason": o.reason, "at": crate::rfc3339(o.at) })
        })
    }
}

#[cfg(test)]
mod tests {
    use rdock_model::values::Duration;

    use super::*;

    fn rollout(dir: &std::path::Path, canary: Option<&str>) -> Rollout {
        let settings = rdock_model::cluster::Rollout {
            canary: canary.map(str::to_owned),
            soak: Duration::from_secs(30),
            canary_timeout: Duration::from_secs(60),
            ..rdock_model::cluster::Rollout::default()
        };
        Rollout::load(dir, settings, 0).unwrap()
    }

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn the_first_revision_and_rollbacks_go_everywhere_at_once() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rollout(dir.path(), None);
        let online = names(&["b", "a"]);
        r.start(1, false, &online, 100);
        assert_eq!(r.state().phase, Phase::Complete);
        assert_eq!(r.target("a"), 1);
        assert_eq!(r.target("b"), 1);
        r.start(2, true, &online, 110);
        assert_eq!(r.state().phase, Phase::Complete);
        assert_eq!(r.target("b"), 2);
    }

    #[test]
    fn the_canary_takes_the_revision_first_and_the_rest_after_the_soak() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rollout(dir.path(), None);
        let online = names(&["c", "b", "a"]);
        r.start(1, false, &online, 0);
        let events = r.start(2, false, &online, 100);
        assert_eq!(
            events,
            vec![Event::CanaryChosen {
                revision: 2,
                canary: "a".to_owned(),
                instead_of: None
            }]
        );
        assert_eq!((r.target("a"), r.target("b"), r.target("c")), (2, 1, 1));
        assert!(r.offered("a", 2));
        // Another instance's ACK of an older revision changes nothing.
        assert_eq!(
            r.report("b", 1, Verdict::Ack, None, 101),
            Vec::<Event>::new()
        );
        assert_eq!(
            r.report("a", 2, Verdict::Ack, None, 105),
            vec![Event::Soaking { revision: 2 }]
        );
        assert_eq!(r.tick(&online, 134), Vec::<Event>::new());
        assert_eq!(r.target("b"), 1);
        assert_eq!(r.tick(&online, 135), vec![Event::Completed { revision: 2 }]);
        assert_eq!((r.target("b"), r.target("c")), (2, 2));
        assert_eq!(r.state().stable, 2);
        // Kept across a restart of the control plane.
        r.save().unwrap();
        let again = Rollout::load(dir.path(), r.settings().clone(), 2).unwrap();
        assert_eq!(again.state(), r.state());
    }

    #[test]
    fn a_refusal_halts_and_the_others_stay_on_the_stable_revision() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rollout(dir.path(), Some("b"));
        let online = names(&["a", "b", "c"]);
        r.start(1, false, &online, 0);
        r.start(2, false, &online, 10);
        assert_eq!(r.state().canary.as_deref(), Some("b"));
        r.offered("b", 2);
        let events = r.report("b", 2, Verdict::Nack, Some("port in use"), 12);
        assert!(
            matches!(&events[..], [Event::Halted { revision: 2, halt }] if halt.reason.contains("port in use"))
        );
        assert_eq!(r.state().phase, Phase::Halted);
        // Time does not move a halted rollout on.
        assert_eq!(r.tick(&online, 10_000), Vec::<Event>::new());
        assert_eq!((r.target("a"), r.target("c")), (1, 1));
        // The canary was given the revision and keeps being offered it (it refused it, so it
        // waits for a newer one).
        assert_eq!(r.target("b"), 2);
        assert_eq!(r.outcome_of(2).unwrap()["state"], "halted");
        // Resume: everyone is given it.
        r.resume("operator", 20).unwrap();
        assert_eq!((r.target("a"), r.target("c")), (2, 2));
        assert!(r.resume("operator", 21).is_err());
        assert!(r.abandon_target().is_err());
    }

    #[test]
    fn abandon_returns_to_the_stable_revision_and_a_new_publication_supersedes() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rollout(dir.path(), None);
        let online = names(&["a", "b"]);
        r.start(1, false, &online, 0);
        r.start(2, false, &online, 10);
        r.offered("a", 2);
        r.report("a", 2, Verdict::Nack, None, 11);
        assert_eq!(r.abandon_target(), Ok(1));
        r.abandoned("operator", 12);
        r.start(3, true, &online, 12);
        assert_eq!(r.state().phase, Phase::Complete);
        assert_eq!((r.target("a"), r.target("b")), (3, 3));
        assert_eq!(r.outcome_of(2).unwrap()["state"], "abandoned");
        // A publication while a rollout runs supersedes it; the stable revision stays.
        r.start(4, false, &online, 20);
        r.start(5, false, &online, 21);
        assert_eq!(r.outcome_of(4).unwrap()["state"], "superseded");
        assert_eq!(r.state().stable, 3);
        assert_eq!(r.target("b"), 3);
    }

    #[test]
    fn an_offline_canary_is_replaced_and_a_silent_one_halts() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rollout(dir.path(), Some("z"));
        r.start(1, false, &names(&["a"]), 0);
        // The named canary is offline: the first online instance by name is chosen.
        let events = r.start(2, false, &names(&["b", "a"]), 10);
        assert_eq!(
            events,
            vec![Event::CanaryChosen {
                revision: 2,
                canary: "a".to_owned(),
                instead_of: Some("z".to_owned())
            }]
        );
        // No report within canary_timeout (60s): halt.
        assert_eq!(r.tick(&[], 69), Vec::<Event>::new());
        let events = r.tick(&[], 70);
        assert!(
            matches!(&events[..], [Event::Halted { halt, .. }] if halt.reason.contains("did not report"))
        );
        // No instance online at publication: the first one to come online is chosen.
        let mut r = rollout(dir.path(), None);
        r.start(1, false, &[], 0);
        r.start(2, false, &[], 5);
        assert_eq!(r.state().canary, None);
        assert_eq!(r.target("a"), 1);
        assert_eq!(r.tick(&names(&["q"]), 6).len(), 1);
        assert_eq!(r.target("q"), 2);
    }

    #[test]
    fn mode_all_keeps_the_behaviour_of_step_five() {
        let dir = tempfile::tempdir().unwrap();
        let settings = rdock_model::cluster::Rollout {
            mode: RolloutMode::All,
            ..rdock_model::cluster::Rollout::default()
        };
        let mut r = Rollout::load(dir.path(), settings, 0).unwrap();
        r.start(1, false, &names(&["a", "b"]), 0);
        r.start(2, false, &names(&["a", "b"]), 1);
        assert_eq!((r.target("a"), r.target("b")), (2, 2));
        // A refusal is listed with the revision but halts nothing.
        assert_eq!(
            r.report("a", 2, Verdict::Nack, None, 2),
            Vec::<Event>::new()
        );
    }

    #[test]
    fn a_refusal_after_completion_is_listed_but_holds_nobody_back() {
        let dir = tempfile::tempdir().unwrap();
        let mut r = rollout(dir.path(), None);
        let online = names(&["a", "b"]);
        r.start(1, false, &online, 0);
        r.start(2, false, &online, 1);
        r.report("a", 2, Verdict::Ack, None, 2);
        r.tick(&online, 40);
        assert_eq!(
            r.report("b", 2, Verdict::Nack, None, 41),
            Vec::<Event>::new()
        );
        assert_eq!(r.state().phase, Phase::Complete);
    }
}
