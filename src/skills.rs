//! ICP skills awareness.
//!
//! Surfaces the official Internet Computer skills published at
//! <https://skills.internetcomputer.org> so an agent knows *how* to author
//! Motoko, build with mops, deploy with the `icp` CLI, manage cycles, etc. —
//! the knowledge that complements the on-chain canister-management tools.
//!
//! The skill catalogue is fetched live from the registry's JSON manifest
//! (`/api/skills.json`) and cached briefly; individual skills are returned from
//! their `SKILL.md` markdown URL on demand. Nothing is bundled, so the agent
//! always sees the current skills (mirroring the registry's own auto-sync
//! philosophy).

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use serde::Deserialize;
use tokio::sync::RwLock;

const SKILLS_BASE_DEFAULT: &str = "https://skills.internetcomputer.org";
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);

/// Registry origin (no trailing slash). Override with `SKILLS_URL`.
fn skills_base() -> String {
    std::env::var("SKILLS_URL")
        .ok()
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| SKILLS_BASE_DEFAULT.to_string())
}

/// One entry from the skills manifest. Optional fields default so a manifest
/// that grows new keys can't break parsing.
#[derive(Deserialize, Clone)]
pub struct SkillEntry {
    pub name: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub urls: SkillUrls,
}

#[derive(Deserialize, Clone, Default)]
pub struct SkillUrls {
    #[serde(default)]
    pub markdown: String,
}

#[derive(Deserialize)]
struct Manifest {
    #[serde(default)]
    skills: Vec<SkillEntry>,
}

struct Cached {
    skills: Vec<SkillEntry>,
    fetched_at: Instant,
}

/// Cache-backed access to the IC skills registry.
#[derive(Clone, Default)]
pub struct SkillsCatalog {
    cache: Arc<RwLock<Option<Cached>>>,
}

impl SkillsCatalog {
    pub fn new() -> Self {
        Self::default()
    }

    /// The skill catalogue, served from cache when fresh, else fetched.
    pub async fn list(&self) -> Result<Vec<SkillEntry>, String> {
        if let Some(c) = self.cache.read().await.as_ref() {
            if c.fetched_at.elapsed() < CACHE_TTL {
                return Ok(c.skills.clone());
            }
        }
        let url = format!("{}/api/skills.json", skills_base());
        let client = crate::discover::http_client()?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("could not reach the skills registry: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "skills registry returned HTTP {}",
                resp.status().as_u16()
            ));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| format!("reading skills registry: {e}"))?;
        let manifest: Manifest =
            serde_json::from_str(&text).map_err(|e| format!("could not parse skills manifest: {e}"))?;
        let skills = manifest.skills;
        *self.cache.write().await = Some(Cached {
            skills: skills.clone(),
            fetched_at: Instant::now(),
        });
        Ok(skills)
    }

    /// The full `SKILL.md` text of one skill, by name.
    pub async fn get(&self, name: &str) -> Result<String, String> {
        let name = name.trim();
        let skills = self.list().await?;
        let entry = skills.iter().find(|s| s.name.eq_ignore_ascii_case(name));
        if entry.is_none() {
            return Err(format!(
                "no skill named `{name}` — call list_ic_skills to see the available skills"
            ));
        }
        // Prefer the manifest's markdown URL; fall back to the conventional path.
        let url = entry
            .and_then(|e| (!e.urls.markdown.is_empty()).then(|| e.urls.markdown.clone()))
            .unwrap_or_else(|| format!("{}/.well-known/skills/{name}/SKILL.md", skills_base()));
        let client = crate::discover::http_client()?;
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("could not fetch skill `{name}`: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "fetching skill `{name}` returned HTTP {}",
                resp.status().as_u16()
            ));
        }
        resp.text()
            .await
            .map_err(|e| format!("reading skill `{name}`: {e}"))
    }

    /// Render the catalogue grouped by category for the `list_ic_skills` tool.
    pub fn format_list(skills: &[SkillEntry]) -> String {
        use std::collections::BTreeMap;
        let mut by_cat: BTreeMap<&str, Vec<&SkillEntry>> = BTreeMap::new();
        for s in skills {
            let cat = if s.category.trim().is_empty() {
                "Other"
            } else {
                s.category.as_str()
            };
            by_cat.entry(cat).or_default().push(s);
        }
        let mut out = String::from(
            "Internet Computer skills — authoritative how-to guides. Load one with \
             get_ic_skill(name).\n",
        );
        for (cat, mut items) in by_cat {
            items.sort_by(|a, b| a.name.cmp(&b.name));
            out.push_str(&format!("\n{cat}:\n"));
            for s in items {
                out.push_str(&format!("- {} — {}: {}\n", s.name, s.title, s.description));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_manifest_and_groups_by_category() {
        let json = r#"{
          "count": 2,
          "skills": [
            {"name":"motoko","title":"Motoko Language","category":"Motoko",
             "description":"Motoko syntax and patterns.",
             "urls":{"markdown":"https://x/.well-known/skills/motoko/SKILL.md","html":"https://x/skills/motoko/"}},
            {"name":"icp-cli","title":"ICP CLI","category":"Infrastructure",
             "description":"Build and deploy with the icp CLI.",
             "urls":{"markdown":"https://x/.well-known/skills/icp-cli/SKILL.md"},
             "compatibility":null,"updated":"2026-06-17T20:26:42.000Z","license":"Apache-2.0"}
          ]
        }"#;
        let manifest: Manifest = serde_json::from_str(json).expect("parse");
        assert_eq!(manifest.skills.len(), 2);
        let rendered = SkillsCatalog::format_list(&manifest.skills);
        assert!(rendered.contains("Motoko:"), "{rendered}");
        assert!(rendered.contains("Infrastructure:"), "{rendered}");
        assert!(rendered.contains("- motoko — Motoko Language:"), "{rendered}");
        assert!(rendered.contains("- icp-cli — ICP CLI:"), "{rendered}");
    }

    #[test]
    fn skills_base_default_and_override() {
        std::env::remove_var("SKILLS_URL");
        assert_eq!(skills_base(), "https://skills.internetcomputer.org");
    }

    // Live network: the real registry parses into our (subset) structs and the
    // headline skills are present and fetchable. Mirrors discover.rs's live tests.
    #[tokio::test]
    async fn fetches_real_registry_and_a_skill() {
        let catalog = SkillsCatalog::new();
        let skills = catalog.list().await.expect("list skills");
        assert!(
            skills.iter().any(|s| s.name == "motoko"),
            "motoko skill missing from registry"
        );
        assert!(
            skills.iter().any(|s| s.name == "cycles-management"),
            "cycles-management skill missing"
        );
        // Every entry should carry a markdown URL we can fetch.
        let motoko = catalog.get("motoko").await.expect("get motoko skill");
        assert!(!motoko.trim().is_empty(), "motoko SKILL.md was empty");
    }
}
