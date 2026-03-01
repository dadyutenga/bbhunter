# BBHunter v2.0 — AI Provider System Implementation Plan

## Overview
Replace the hardcoded Claude API dependency with a flexible **multi-provider AI system**.
The tool will support GitHub Copilot, Claude, OpenAI Codex, Ollama (local), and any
future provider — all selectable at startup or via CLI commands.

---

## Branch Setup
```bash
make  sure  we   are  on  this   branch 
 feature/ai-provider-system
```

---

## Architecture

```
bbhunter/
├── ai/
│   ├── __init__.py
│   ├── base_provider.py        # Abstract base class for all providers
│   ├── providers/
│   │   ├── __init__.py
│   │   ├── github_copilot.py   # GitHub Copilot provider
│   │   ├── claude.py           # Anthropic Claude provider
│   │   ├── openai.py           # OpenAI / Codex provider
│   │   └── ollama.py           # Local Ollama provider
│   ├── model_registry.py       # /models command — lists available models
│   └── connector_manager.py    # /connectors command — manages providers
├── config/
│   └── providers.json          # Saved provider configs & auth tokens
└── core/
    └── agent.py                # Main agent — uses active provider
```

---

## Phase 1 — Base Provider Interface

**File:** `ai/base_provider.py`

```python
from abc import ABC, abstractmethod

class BaseProvider(ABC):
    name: str
    requires_auth: bool

    @abstractmethod
    def authenticate(self) -> bool:
        """Handle login/token setup"""
        pass

    @abstractmethod
    def list_models(self) -> list[dict]:
        """Return available models for this provider"""
        pass

    @abstractmethod
    def chat(self, messages: list, model: str = None) -> str:
        """Send messages and return response"""
        pass

    @abstractmethod
    def is_connected(self) -> bool:
        """Check if provider is authenticated and ready"""
        pass
```

---

## Phase 2 — GitHub Copilot Provider

**File:** `ai/providers/github_copilot.py`

### Auth Flow
1. Check if `gh` CLI is installed → `gh auth status`
2. If not logged in → run `gh auth login`
3. Get Copilot token via `gh copilot` or GitHub API
4. Store token in `config/providers.json`

### Models to expose
| Model ID | Display Name |
|---|---|
| `gpt-4o` | GPT-4o (Copilot) |
| `gpt-4o-mini` | GPT-4o Mini (Copilot) |
| `claude-3.5-sonnet` | Claude 3.5 Sonnet (Copilot) |
| `o1-mini` | o1-mini (Copilot) |

### API Endpoint
```
POST https://api.githubcopilot.com/chat/completions
Headers:
  Authorization: Bearer <copilot_token>
  Editor-Version: vscode/1.85.0
  Copilot-Integration-Id: vscode-chat
```

---

## Phase 3 — CLI Commands

### `/connectors` — List & manage providers
```
┌─────────────────────────────────────────────────┐
│  CONNECTORS                                     │
├──────────────────┬────────────┬─────────────────┤
│  Provider        │  Status    │  Action         │
├──────────────────┼────────────┼─────────────────┤
│  GitHub Copilot  │  ✅ Active  │  [disconnect]   │
│  Claude          │  ❌ No key  │  [connect]      │
│  OpenAI          │  ❌ No key  │  [connect]      │
│  Ollama (local)  │  ✅ Running │  [use]          │
└──────────────────┴────────────┴─────────────────┘
```

### `/models` — List available models
```
┌──────────────────────────────────────────────────┐
│  AVAILABLE MODELS                                │
├──────────────────────┬───────────────────────────┤
│  Provider            │  Models                   │
├──────────────────────┼───────────────────────────┤
│  GitHub Copilot ✅   │  gpt-4o, claude-3.5-sonnet│
│  Ollama ✅           │  llama3, mistral, codellama│
│  Claude ❌           │  (connect first)           │
└──────────────────────┴───────────────────────────┘

> Select model: _
```

### `/use <provider> <model>` — Switch active model
```bash
/use copilot gpt-4o
/use ollama llama3
/use claude claude-3-opus
```

---

## Phase 4 — Startup Flow

```
BBHunter v2.0 starting...

┌─────────────────────────────────┐
│  No AI provider configured.     │
│  Select a provider to continue: │
│                                 │
│  1. GitHub Copilot (recommended)│
│  2. Claude (API key required)   │
│  3. OpenAI (API key required)   │
│  4. Ollama (local, free)        │
│  5. Skip (limited mode)         │
└─────────────────────────────────┘
> 1

→ Checking GitHub CLI... ✅ found
→ Checking auth status... ❌ not logged in
→ Running: gh auth login
→ [browser opens for OAuth]
→ Authenticated as dadyutenga ✅
→ Fetching Copilot token... ✅
→ Loading models... gpt-4o, gpt-4o-mini, claude-3.5-sonnet

BBHunter ready. Active: GitHub Copilot / gpt-4o
```

---

## Phase 5 — Connector Manager

**File:** `ai/connector_manager.py`

```python
class ConnectorManager:
    def list_connectors(self) -> list[dict]:
        """Return all providers with their status"""

    def connect(self, provider_name: str) -> bool:
        """Trigger auth flow for a provider"""

    def disconnect(self, provider_name: str):
        """Remove saved credentials"""

    def get_active(self) -> BaseProvider:
        """Return the currently active provider"""

    def set_active(self, provider_name: str, model: str):
        """Switch active provider and model"""
```

---

## Phase 6 — Config Storage

**File:** `config/providers.json`
```json
{
  "active_provider": "github_copilot",
  "active_model": "gpt-4o",
  "providers": {
    "github_copilot": {
      "token": "ghu_xxxx",
      "token_expires": "2026-04-01T00:00:00Z",
      "last_used": "2026-03-01"
    },
    "ollama": {
      "base_url": "http://localhost:11434",
      "last_used": "2026-02-28"
    }
  }
}
```

---

## Implementation Order

| Step | Task | Branch Commit |
|---|---|---|
| 1 | Create branch + folder structure | `chore: scaffold ai provider system` |
| 2 | `base_provider.py` abstract class | `feat: add BaseProvider interface` |
| 3 | `github_copilot.py` provider | `feat: add GitHub Copilot provider` |
| 4 | `connector_manager.py` | `feat: add ConnectorManager` |
| 5 | `model_registry.py` + `/models` cmd | `feat: add /models command` |
| 6 | `/connectors` cmd UI | `feat: add /connectors command` |
| 7 | Startup flow + provider selection | `feat: add startup provider selection` |
| 8 | Config persistence | `feat: add provider config persistence` |
| 9 | Swap agent.py to use active provider | `refactor: wire agent to provider system` |
| 10 | PR → main | `merge: feature/ai-provider-system` |

---

## First Commands to Run Right Now

```bash
# 1. Create the branch
git checkout main && git pull origin main
git checkout -b feature/ai-provider-system
git push -u origin feature/ai-provider-system

# 2. Create folder structure
mkdir -p ai/providers config

# 3. Create empty init files
New-Item ai/__init__.py, ai/providers/__init__.py -ItemType File

# 4. First commit
git add .
git commit -m "chore: scaffold ai provider system"
git push
```

---

> **Next step:** Start with `ai/base_provider.py` then `ai/providers/github_copilot.py`
