# Zahra Dashboard — Live Attack Monitoring UI

Build a real-time dashboard for the **Zahra AI Pentest Swarm Platform** that
displays live attack progress from the backend's WebSocket endpoint.

## Backend Connection

The backend exposes a WebSocket at:

```
ws://localhost:8000/ws/attack
```

### Connecting

1. Open a WebSocket connection to `/ws/attack`.
2. The server sends a welcome message:
   ```json
   {"type": "system", "message": "Connected to Zahra live attack stream. Send a command to start."}
   ```
3. To start an attack, send a JSON command:
   ```json
   {"command": "recon example.com", "auto_run": true}
   ```
   Supported commands: `recon <target>`, `scan <target>`, `exploit <target>`, `full <target>`.

### Incoming Event Types

The server streams JSON events. Handle these types:

| Event Type | Payload Fields | Description |
|-----------|----------------|-------------|
| `system` | `message` | Connection / system messages |
| `campaign_created` | `campaign_id`, `target`, `intent` | A new campaign was created |
| `campaign_starting` | `campaign_id` | Campaign is about to run |
| `orchestrator` | `campaign_id`, `type` (e.g. `campaign_started`, `campaign_completed`, `campaign_error`), `findings` | Orchestrator lifecycle events |
| `swarm` | `agent` (e.g. `recon_agent`, `scan_agent`, `exploit_agent`), `type` (e.g. `agent_started`, `agent_finished`, `agent_error`), `findings`, `duration` | Per-agent status events |
| `error` | `message` | An error occurred |

Example swarm event:
```json
{
  "type": "swarm",
  "agent": "recon_agent",
  "type": "agent_started",
  "target": "example.com",
  "timestamp": 1710000000.0
}
```

## Dashboard Requirements

Build a single-page dashboard with the following sections:

### 1. Agent Status Cards

Display one card per agent (Recon, Scan, Exploit). Each card shows:
- **Agent name** (e.g. "Recon Agent")
- **Status** — Idle / Running / Finished / Error (color-coded)
- **Findings count** — number of findings discovered
- **Duration** — how long the agent has been running (or total time when finished)
- **Last activity** — timestamp of the last event

Cards should update live as events arrive over the WebSocket.

### 2. Live Terminal View

A terminal-style log panel that shows the **live output** from the swarm.
Each log line should include:
- Timestamp
- Agent name (color-coded per agent)
- Log message (e.g. "executing: nmap -sV -T4 --top-ports 100 example.com")

The terminal should auto-scroll to the bottom as new lines arrive.

### 3. Campaign Controls

- A text input for the target (e.g. `example.com`)
- Buttons: **Recon**, **Scan**, **Exploit**, **Full Pentest**
- Clicking a button sends the corresponding command over the WebSocket
- A "Disconnect" / "Connect" toggle for the WebSocket

### 4. Findings Panel

A collapsible panel that lists findings as they are discovered. Each finding
shows:
- Severity (color-coded: critical=red, high=orange, medium=yellow, low=blue, info=gray)
- Type (recon, vuln, credential, error)
- Description
- Agent that found it
- Confidence percentage

## Design Guidelines

- **Dark theme** — security tool aesthetic (dark background, monospace fonts)
- **Responsive** — works on desktop and mobile
- **Real-time** — no page reloads; everything updates via WebSocket
- **Accessible** — clear contrast, semantic HTML, ARIA labels where useful
- **Self-contained** — a single `index.html` (or a small set of files) that
  can be opened directly or served statically

## Tech Suggestions

- Plain HTML/CSS/JS (no build step) for simplicity, OR
- A lightweight framework (React/Vue via CDN) if preferred
- Use the native `WebSocket` API — no external libraries needed

## Deliverable

Produce the dashboard files in a `dashboard/` directory at the project root:
- `dashboard/index.html`
- `dashboard/styles.css` (or inline)
- `dashboard/app.js` (or inline)

The dashboard should connect to `ws://localhost:8000/ws/attack` by default,
with a configurable URL field in the UI.