"""
AI Schedule Assistant for the Matiz PM Tool.

This module never touches the database. It only:

  1. works out which workflow phases a client still needs, using the PM Tool's
     OWN workflow (the STAGES pipeline and the service's `hasImplementation`
     flag from SERVICES in server.py — the same rule the front end uses in
     clientWorkSteps()),
  2. asks an existing hosted LLM for a recommended date plan, and
  3. strictly validates whatever comes back (or whatever the manager edited)
     before server.py is allowed to show or save it.

server.py owns the permission check, the stale-data check and the actual
UPDATE of the existing date columns, and only after the manager clicks
"Accept Schedule".

Configuration (environment variables, never hard-coded, never sent to the browser):

  LLM_API_KEY            required. Your OpenAI API key (OPENAI_API_KEY also works).
  LLM_MODEL              optional. Default "gpt-5-mini" (low cost, reasoning model).
  LLM_REASONING_EFFORT   optional. Default "low" (minimal / low / medium / high).
  LLM_TIMEOUT_SECONDS    optional. Default 45 per OpenAI call.
"""

import hashlib
import json
import os
import re
import time
from datetime import date, timedelta


class SchedulingError(Exception):
    """A problem that is safe to show to the manager as-is (no secrets, no
    stack traces). `code` is the HTTP status server.py should answer with."""

    def __init__(self, msg, code=400, retryable=False, feedback=""):
        super().__init__(msg)
        self.msg = msg
        self.code = code
        self.retryable = retryable   # True = the model's answer was bad; worth one automatic retry
        self.feedback = feedback     # precise correction sent back to the model on that retry


# =====================================================================
# WORKFLOW PHASES — derived from the existing pipeline, not invented here.
# ---------------------------------------------------------------------
# Each phase is a contiguous block of the existing STAGES list (identified by
# its first and last stage name), plus the EXISTING client columns that
# already hold that phase's start date and deadline (added earlier for the
# "Assign Work" tab). Nothing new is stored.
#
#   needs_impl=True  -> only for services whose SERVICES[...]["hasImplementation"]
#                       is True (SCI, Scopus paid). Other services go straight
#                       from "Sent to Technical Team" to Paper Writing — exactly
#                       what assign_proposal_writer / tmNewWorkQueue enforce.
#   JOURNAL          -> the Journal Team part of the pipeline (proofreading,
#                       formatting, submission). It has no dedicated date
#                       columns, so it is planned and displayed but its end is
#                       the client's existing final deadline (deadline_date).
#
# min_days / typical_days are planning HINTS for the model and for the
# "deadline looks too short" warning. They do not change the workflow.
# =====================================================================
PHASE_DEFS = [
    {"key": "PROPOSAL", "name": "Proposal",
     "first": "PROPOSAL_ASSIGNED", "last": "PROPOSAL_APPROVED",
     "start_col": "proposal_start_date", "end_col": "proposal_deadline",
     "task_type": "PROPOSAL", "pre_people_col": None, "pre_deadline_col": None,
     "needs_impl": True, "min_days": 2, "typical_days": 7,
     "hint": "Proposal writing, internal verification by Technical TL/Manager, delivery and client approval."},
    {"key": "IMPLEMENTATION", "name": "Code Implementation",
     "first": "IMPLEMENTATION_ASSIGNED", "last": "IMPLEMENTATION_APPROVED",
     "start_col": "implementation_start_date", "end_col": "implementation_deadline",
     "task_type": "IMPLEMENTATION",
     "pre_people_col": "pre_impl_programmers", "pre_deadline_col": "pre_impl_deadline",
     "needs_impl": True, "min_days": 4, "typical_days": 14,
     "hint": "Programmers build the code, demo it, Technical TL/Manager approve, client approves."},
    {"key": "PAPER_WRITING", "name": "Paper Writing",
     "first": "PAPERWRITER_ASSIGNED", "last": "CLIENT_ACCEPTED",
     "start_col": "writing_start_date", "end_col": "writing_deadline",
     "task_type": "PAPER_WRITING",
     "pre_people_col": "pre_write_writers", "pre_deadline_col": "pre_write_deadline",
     "needs_impl": False, "min_days": 4, "typical_days": 10,
     "hint": "Paper writing, coordinator / Technical TL / Manager review rounds, corrections, client approval."},
    {"key": "JOURNAL", "name": "Final Review & Journal Submission",
     "first": "JOURNAL_MANAGER_REVIEW", "last": "JOURNAL_SUBMITTED",
     "start_col": None, "end_col": None,
     "task_type": None, "pre_people_col": None, "pre_deadline_col": None,
     "needs_impl": False, "min_days": 2, "typical_days": 5,
     "hint": "Journal Manager review, proofreading, formatting and submission to the journal."},
]
PHASE_BY_KEY = {p["key"]: p for p in PHASE_DEFS}

RISK_LEVELS = ("LOW", "MEDIUM", "HIGH")
MAX_REASON_CHARS = 800
MAX_NOTE_CHARS = 500
MAX_WARNING_CHARS = 300


# ---------------------------------------------------------------------
# small date helpers
# ---------------------------------------------------------------------
def parse_iso_date(value):
    """'YYYY-MM-DD' (optionally followed by a time) -> date, else None."""
    if value is None:
        return None
    if isinstance(value, date):
        return value
    s = str(value).strip()
    m = re.match(r"^(\d{4})-(\d{2})-(\d{2})", s)
    if not m:
        return None
    try:
        return date(int(m.group(1)), int(m.group(2)), int(m.group(3)))
    except ValueError:
        return None


def days_inclusive(start, end):
    """Calendar days from start to end, counting both ends (25 Sep–25 Sep = 1)."""
    return (end - start).days + 1


def _row_get(row, key):
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return None


# =====================================================================
# 1) CONTEXT — what we know about this client, from existing DB fields
# =====================================================================
def workflow_phases(service_conf):
    """The phases this service goes through, in order, per the existing rules."""
    has_impl = bool(service_conf.get("hasImplementation"))
    return [p for p in PHASE_DEFS if has_impl or not p["needs_impl"]]


def _phase_status(stage, phase, stages):
    """'done' / 'active' / 'pending' for this phase given the client's stage,
    using positions in the existing STAGES list."""
    if stage == "COMPLETED":
        return "done"
    try:
        idx = stages.index(stage)
        first = stages.index(phase["first"])
        last = stages.index(phase["last"])
    except ValueError:
        return "pending"
    if idx > last:
        return "done"
    if idx >= first:
        return "active"
    return "pending"


def build_context(client, service_conf, stages, stage_labels, today=None):
    """Everything the AI (and the validator) needs, built only from the
    existing client row. Raises SchedulingError for cases that can't be
    scheduled at all (no deadline, deadline passed, nothing left, etc.)."""
    today = today or date.today()

    if _row_get(client, "rejected"):
        raise SchedulingError("This client is marked as rejected, so there is nothing to schedule.")

    stage = _row_get(client, "stage") or "NEW"
    if stage == "COMPLETED":
        raise SchedulingError("This project is already completed — there is nothing left to schedule.")

    deadline_raw = (_row_get(client, "deadline_date") or "").strip()
    if not deadline_raw:
        raise SchedulingError("This client has no final deadline yet. Set the project deadline first, "
                              "then generate an AI schedule.")
    deadline = parse_iso_date(deadline_raw)
    if not deadline:
        raise SchedulingError("The client's final deadline (%s) isn't a valid date. Correct it first."
                              % deadline_raw[:20])
    if deadline < today:
        raise SchedulingError("The client's final deadline (%s) has already passed. Agree a new deadline "
                              "with the client (Date Extensions) before scheduling." % deadline.isoformat())

    warnings = []
    reg = parse_iso_date(_row_get(client, "reg_date"))
    if not reg:
        reg = parse_iso_date(_row_get(client, "created_at")) or today
        warnings.append("The registration date is missing or invalid, so %s was used instead." % reg.isoformat())
    if reg > deadline:
        raise SchedulingError("The registration date (%s) is after the final deadline (%s). "
                              "Correct the client's dates first." % (reg.isoformat(), deadline.isoformat()))

    # Plan from today (past days can't be scheduled) unless the client
    # registers in the future, in which case plan from the registration date.
    window_start = max(today, reg)

    all_phases = workflow_phases(service_conf)
    phases, done = [], []
    for p in all_phases:
        status = _phase_status(stage, p, stages)
        existing_start = parse_iso_date(_row_get(client, p["start_col"])) if p["start_col"] else None
        existing_end = parse_iso_date(_row_get(client, p["end_col"])) if p["end_col"] else None
        info = {
            "key": p["key"], "name": p["name"], "status": status,
            "existing_start": existing_start.isoformat() if existing_start else "",
            "existing_end": existing_end.isoformat() if existing_end else "",
            "min_days": p["min_days"], "typical_days": p["typical_days"], "hint": p["hint"],
            "saves_dates": bool(p["end_col"]),
        }
        (done if status == "done" else phases).append(info)

    if not phases:
        raise SchedulingError("Every scheduled phase of this project is already finished — "
                              "there is nothing left to schedule.")

    # The first remaining phase starts on a fixed day: if it's already in
    # progress and has a recorded start date, keep that (work already began);
    # otherwise it starts at the planning window start.
    first = phases[0]
    locked = parse_iso_date(first["existing_start"]) if first["status"] == "active" else None
    if not locked or locked > today or locked > deadline:
        locked = window_start
    first["locked_start"] = locked.isoformat()
    schedule_start = locked

    available_days = days_inclusive(schedule_start, deadline)
    if available_days < len(phases):
        raise SchedulingError(
            "Impossible schedule: only %d day(s) remain until the final deadline (%s) but %d phase(s) "
            "still need at least one day each. Extend the deadline first."
            % (available_days, deadline.isoformat(), len(phases)))

    min_total = sum(p["min_days"] for p in phases)
    typical_total = sum(p["typical_days"] for p in phases)
    if available_days < min_total:
        warnings.append("The deadline looks too short: %d day(s) available but these phases usually need "
                        "at least %d. Expect high risk, or ask for a deadline extension."
                        % (available_days, min_total))
    if _row_get(client, "on_hold"):
        warnings.append("This project is currently ON HOLD — the schedule assumes work resumes immediately.")

    fingerprint = compute_fingerprint(client)
    return {
        "client_id": _row_get(client, "id"),
        "client_name": _row_get(client, "name") or "",
        "service_key": _row_get(client, "service_key") or "",
        "service_label": service_conf.get("label", ""),
        "has_implementation": bool(service_conf.get("hasImplementation")),
        "current_stage": stage,
        "current_stage_label": stage_labels.get(stage, stage),
        "registration_date": reg.isoformat(),
        "final_deadline": deadline.isoformat(),
        "today": today.isoformat(),
        "schedule_start": schedule_start.isoformat(),
        "available_days": available_days,
        "min_total_days": min_total,
        "typical_total_days": typical_total,
        "workflow": [p["name"] for p in all_phases],
        "phases": phases,
        "completed_phases": [{"key": p["key"], "name": p["name"]} for p in done],
        "warnings": warnings,
        "fingerprint": fingerprint,
    }


def compute_fingerprint(client):
    """Short hash of everything a schedule depends on. If any of it changes
    between 'Generate' and 'Accept', the accept is refused as stale."""
    parts = [str(_row_get(client, k) or "") for k in (
        "id", "stage", "service_key", "reg_date", "deadline_date",
        "proposal_start_date", "implementation_start_date", "writing_start_date")]
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]


# =====================================================================
# 2) LLM CALL — OpenAI only
# ---------------------------------------------------------------------
# Small models are good at judgement ("implementation needs the biggest
# share") but unreliable at calendar arithmetic. So the model only decides
# HOW MANY DAYS each phase gets (plus risk and a reason); this server turns
# those durations into exact back-to-back dates. The model therefore can't
# produce an impossible date, a wrong day count or an overlap — and the result
# is still fully validated afterwards like anything else.
#
# The reply shape is enforced with OpenAI Structured Outputs (a strict JSON
# schema whose phase keys are an enum of exactly this project's phases).
# =====================================================================
DEFAULT_MODEL = "gpt-5-mini"          # low-cost model with built-in reasoning
TOTAL_BUDGET_SECONDS = 100            # whole generate step, under gunicorn's --timeout 120

SYSTEM_PROMPT = """You are a project-scheduling assistant in a research-services project management tool.
Your job: decide how many calendar days each remaining workflow phase of a project should get, between the planning start date and the client's final deadline.

The server converts your durations into exact dates: phases run back-to-back in the given order and the first phase starts on schedule_start. You only choose whole-day durations.

Hard rules:
- Return every phase listed in phases_to_schedule, with the same keys, in the same order. Do not add, remove or rename phases.
- Each duration_days is a whole number of at least 1.
- The sum of all duration_days must be less than or equal to available_days. Days left over become buffer before the final deadline.

How to split the time:
- Start from each phase's typical_days and scale proportionally to the time actually available.
- Do not go below a phase's min_days unless available_days makes that impossible.
- If available_days is comfortably more than sum_of_typical_days, keep about 10-15% of the time (at least 2 days) as buffer.
- If time is tight, give up the buffer first, then shorten phases proportionally; protect Code Implementation and Paper Writing the most.
- Follow the manager's preferences when they do not break the hard rules.

Risk:
- LOW: every phase gets about its typical_days or more, and there are 2 or more buffer days.
- MEDIUM: it fits, but buffer is 0-1 days or several phases are below typical_days.
- HIGH: one or more phases are below min_days, or the deadline is unrealistic.

reason: 2-3 short, plain sentences for a busy manager: how the time was split and the main risk.
warnings: short concrete concerns (an empty list if there are none).

Always answer with a single JSON object matching the required schema."""


def build_user_prompt(context, manager_note=""):
    """Only scheduling facts go to the LLM — no client name, phone, email or
    payment data."""
    phases = context["phases"]
    payload = {
        "service": context["service_label"],
        "workflow_for_this_service": context["workflow"],
        "already_completed_phases": [p["name"] for p in context["completed_phases"]],
        "current_stage": context["current_stage_label"],
        "schedule_start": context["schedule_start"],
        "final_deadline": context["final_deadline"],
        "available_days": context["available_days"],
        "sum_of_typical_days": sum(p["typical_days"] for p in phases),
        "sum_of_min_days": sum(p["min_days"] for p in phases),
        "phases_to_schedule": [{
            "key": p["key"], "name": p["name"],
            "status": "in progress" if p["status"] == "active" else "not started",
            "min_days": p["min_days"], "typical_days": p["typical_days"],
            "what_happens": p["hint"],
        } for p in phases],
    }
    text = "Plan this project (JSON):\n" + json.dumps(payload, indent=2)
    note = (manager_note or "").strip()[:MAX_NOTE_CHARS]
    if note:
        text += ("\n\nManager's preferences for this plan (follow only within the hard rules):\n" + note)
    return text


def response_schema(phase_keys):
    """Strict JSON schema for OpenAI Structured Outputs."""
    return {
        "name": "project_schedule",
        "strict": True,
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "required": ["stages", "risk", "reason", "warnings"],
            "properties": {
                "stages": {"type": "array", "items": {
                    "type": "object", "additionalProperties": False,
                    "required": ["key", "duration_days"],
                    "properties": {
                        "key": {"type": "string", "enum": list(phase_keys)},
                        "duration_days": {"type": "integer"},
                    }}},
                "risk": {"type": "string", "enum": list(RISK_LEVELS)},
                "reason": {"type": "string"},
                "warnings": {"type": "array", "items": {"type": "string"}},
            },
        },
    }


def _llm_settings():
    # LLM_API_KEY is the documented name; OPENAI_API_KEY is accepted too.
    key = (os.environ.get("LLM_API_KEY") or os.environ.get("OPENAI_API_KEY") or "").strip()
    model = (os.environ.get("LLM_MODEL") or DEFAULT_MODEL).strip()
    try:
        timeout = float(os.environ.get("LLM_TIMEOUT_SECONDS") or 45)
    except ValueError:
        timeout = 45.0
    timeout = max(10.0, min(timeout, 90.0))
    effort = (os.environ.get("LLM_REASONING_EFFORT") or "low").strip().lower()
    if effort not in ("none", "minimal", "low", "medium", "high"):
        effort = "low"
    return key, model, timeout, effort


def is_configured():
    return bool(_llm_settings()[0])


def _supports_reasoning(model):
    m = model.lower()
    return m.startswith("gpt-5") or m.startswith("o1") or m.startswith("o3") or m.startswith("o4")


def _openai_create(openai, client, params):
    """One API call; every failure except 'bad request' becomes a safe message."""
    try:
        return client.chat.completions.create(**params)
    except openai.BadRequestError:
        raise                                  # caller retries with plainer params
    except openai.APITimeoutError:
        raise SchedulingError("The AI service took too long to answer. Please try again.", 504)
    except openai.AuthenticationError:
        raise SchedulingError("OpenAI rejected the server's API key. Ask your administrator to check "
                              "LLM_API_KEY in the Render environment settings.", 503)
    except openai.PermissionDeniedError:
        raise SchedulingError("OpenAI refused this request for the configured account or model. "
                              "Ask your administrator to check the key's permissions and LLM_MODEL.", 503)
    except openai.NotFoundError:
        raise SchedulingError("The configured AI model wasn't found for this OpenAI account. "
                              "Ask your administrator to check LLM_MODEL.", 503)
    except openai.RateLimitError as e:
        if (getattr(e, "code", "") or "") == "insufficient_quota" or "quota" in str(e).lower():
            raise SchedulingError("The OpenAI account has no remaining credit (quota exceeded). Add billing "
                                  "credit at platform.openai.com, then try again.", 503)
        raise SchedulingError("OpenAI is rate-limiting requests right now. Wait a minute and try again.", 503)
    except openai.APIConnectionError:
        raise SchedulingError("Couldn't reach the AI service (network error). Please try again shortly.", 503)
    except openai.APIStatusError:
        raise SchedulingError("The AI service returned an error. Please try again shortly.", 502)
    except openai.OpenAIError:
        raise SchedulingError("The AI service returned an error. Please try again shortly.", 502)


def chat_completion(messages, schema, timeout=None):
    """Send the conversation to OpenAI and return the reply text."""
    key, model, default_timeout, effort = _llm_settings()
    if not key:
        raise SchedulingError("AI scheduling isn't set up on this server yet (no OpenAI API key). "
                              "Ask your administrator to add LLM_API_KEY in the Render environment settings.", 503)
    try:
        import openai
    except ImportError:
        raise SchedulingError("The AI scheduler isn't installed on the server (missing 'openai' package). "
                              "Ask your administrator to redeploy with requirements.txt.", 503)
    client = openai.OpenAI(api_key=key, timeout=timeout or default_timeout, max_retries=0)
    params = {
        "model": model,
        "messages": messages,
        "max_completion_tokens": 4000,     # includes the model's internal reasoning
        "response_format": {"type": "json_schema", "json_schema": schema},
    }
    if _supports_reasoning(model):
        params["reasoning_effort"] = effort
    try:
        resp = _openai_create(openai, client, params)
    except openai.BadRequestError:
        # A model that doesn't support reasoning_effort / strict schemas: retry
        # with the plainest JSON request. The reply is still fully validated.
        params.pop("reasoning_effort", None)
        params["response_format"] = {"type": "json_object"}
        try:
            resp = _openai_create(openai, client, params)
        except openai.BadRequestError:
            raise SchedulingError("OpenAI didn't accept the request for the configured model. "
                                  "Ask your administrator to check LLM_MODEL (default %s)." % DEFAULT_MODEL, 502)
    try:
        choice = resp.choices[0]
        msg = choice.message
    except (AttributeError, IndexError, TypeError):
        raise SchedulingError("The AI returned an empty answer. Click Regenerate to try again.", 502, retryable=True)
    if getattr(msg, "refusal", None):
        raise SchedulingError("The AI declined to produce a schedule. Click Regenerate to try again.", 502)
    content = msg.content or ""
    if not content.strip() and getattr(choice, "finish_reason", "") == "length":
        raise SchedulingError("The AI ran out of room before finishing its answer. Click Regenerate to try again.",
                              502, retryable=True)
    return content


def extract_json(text):
    """Pull the JSON object out of the model's reply (tolerates code fences
    or stray text around it). Raises SchedulingError if there is none."""
    if not text or not text.strip():
        raise SchedulingError("The AI returned an empty answer. Click Regenerate to try again.", 502, retryable=True)
    s = text.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    try:
        obj = json.loads(s)
    except ValueError:
        start, end = s.find("{"), s.rfind("}")
        try:
            obj = json.loads(s[start:end + 1]) if 0 <= start < end else None
        except ValueError:
            obj = None
        if obj is None:
            raise SchedulingError("The AI's answer wasn't valid JSON, so it was discarded. "
                                  "Click Regenerate to try again.", 502, retryable=True)
    if not isinstance(obj, dict):
        raise SchedulingError("The AI's answer wasn't in the expected format, so it was discarded. "
                              "Click Regenerate to try again.", 502, retryable=True)
    return obj


def _phase_name(key):
    p = PHASE_BY_KEY.get(str(key or "").upper())
    return p["name"] if p else "a phase"


def durations_to_dates(context, raw):
    """Turn the model's per-phase durations into exact back-to-back dates,
    starting on the first phase's locked start date. Output uses the same
    shape validate_schedule() checks (start_date / end_date per phase)."""
    stages = raw.get("stages")
    if not isinstance(stages, list) or not stages:
        raise SchedulingError("The AI's answer didn't include any phases. Click Regenerate to try again.",
                              422, retryable=True)
    expected = [p["key"] for p in context["phases"]]
    got = [str((s or {}).get("key") or "").strip().upper() if isinstance(s, dict) else "" for s in stages]
    if got != expected:
        raise SchedulingError(
            "The AI's plan didn't follow this project's workflow (%s)." % " → ".join(
                p["name"] for p in context["phases"]), 422, retryable=True,
            feedback="The phases must be exactly %s, in that order (you returned %s)." % (expected, got))
    durations = []
    for s in stages:
        v = s.get("duration_days")
        try:
            n = int(v)
            if isinstance(v, bool) or float(v) != n:
                raise ValueError
        except (TypeError, ValueError):
            raise SchedulingError("The AI gave an invalid number of days for %s." % _phase_name(s.get("key")),
                                  422, retryable=True,
                                  feedback="Every duration_days must be a whole number (got %r for %s)." % (v, s.get("key")))
        if n < 1:
            raise SchedulingError("The AI gave %s less than 1 day." % _phase_name(s.get("key")), 422, retryable=True,
                                  feedback="Every phase needs at least 1 day (got %d for %s)." % (n, s.get("key")))
        durations.append(n)
    total, available = sum(durations), context["available_days"]
    if total > available:
        raise SchedulingError(
            "The AI's plan needed %d days but only %d days are left before the final deadline." % (total, available),
            422, retryable=True,
            feedback="The durations add up to %d days but only %d days are available between %s and %s. "
                     "Reduce them so the total is %d or less." % (
                         total, available, context["schedule_start"], context["final_deadline"], available))
    d = parse_iso_date(context["phases"][0]["locked_start"])
    out = []
    for key, n in zip(expected, durations):
        end = d + timedelta(days=n - 1)
        out.append({"key": key, "start_date": d.isoformat(), "end_date": end.isoformat(), "duration_days": n})
        d = end + timedelta(days=1)
    return {"stages": out, "risk": raw.get("risk"), "reason": raw.get("reason"),
            "warnings": raw.get("warnings") if isinstance(raw.get("warnings"), list) else []}


# =====================================================================
# 3) VALIDATION — never trust the LLM (or the browser)
# =====================================================================
def _clean_text(value, limit):
    s = str(value or "")
    s = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", s)
    s = re.sub(r"\s+", " ", s).strip()
    return s[:limit]


def validate_schedule(context, proposed, source="ai"):
    """Check a proposed schedule against the context and the existing
    workflow. `source` is "ai" (fresh LLM output) or "manager" (dates the
    manager may have edited, sent back on Accept).

    Returns a normalised dict with every number recomputed server-side.
    Raises SchedulingError describing the first problem found."""
    if not isinstance(proposed, dict):
        raise SchedulingError("The schedule wasn't in the expected format.", 422)
    who = "The AI's schedule" if source == "ai" else "This schedule"
    retry = " Click Regenerate to try again." if source == "ai" else ""

    raw_stages = proposed.get("stages")
    if not isinstance(raw_stages, list) or not raw_stages:
        raise SchedulingError(who + " didn't include any phases." + retry, 422)

    expected = context["phases"]
    exp_keys = [p["key"] for p in expected]
    got_keys = []
    for s in raw_stages:
        if not isinstance(s, dict):
            raise SchedulingError(who + " has a malformed phase entry." + retry, 422)
        k = str(s.get("key") or "").strip().upper()
        if not k:  # tolerate a model that only echoed the name
            nm = str(s.get("name") or "").strip().lower()
            k = next((p["key"] for p in expected if p["name"].lower() == nm), "")
        got_keys.append(k)
    if got_keys != exp_keys:
        raise SchedulingError(
            "%s doesn't follow this project's workflow (expected %s)." % (
                who, " → ".join(p["name"] for p in expected)) + retry, 422)

    deadline = parse_iso_date(context["final_deadline"])
    locked_start = parse_iso_date(expected[0].get("locked_start"))
    stages_out, prev_end = [], None
    for exp, s, _k in zip(expected, raw_stages, got_keys):
        st = parse_iso_date(s.get("start_date"))
        en = parse_iso_date(s.get("end_date"))
        label = exp["name"]
        if not st or not en:
            raise SchedulingError("%s has an invalid date for %s." % (who, label) + retry, 422)
        if st > en:
            raise SchedulingError("%s: %s ends before it starts." % (who, label) + retry, 422)
        if prev_end is None:
            if locked_start and st != locked_start:
                raise SchedulingError("%s: %s must start on %s." % (who, label, locked_start.isoformat()) + retry, 422)
        elif st <= prev_end:
            raise SchedulingError("%s: %s overlaps the previous phase — each phase must start after "
                                  "the previous one ends." % (who, label) + retry, 422)
        if en > deadline:
            raise SchedulingError("%s: %s ends on %s, after the final deadline (%s)."
                                  % (who, label, en.isoformat(), deadline.isoformat()) + retry, 422)
        stages_out.append({
            "key": exp["key"], "name": exp["name"],
            "start_date": st.isoformat(), "end_date": en.isoformat(),
            "duration_days": days_inclusive(st, en),   # recomputed, never the model's number
            "min_days": exp["min_days"], "typical_days": exp["typical_days"],
            "saves_dates": exp["saves_dates"], "status": exp["status"],
            "existing_start": exp["existing_start"], "existing_end": exp["existing_end"],
        })
        prev_end = en

    schedule_start = parse_iso_date(stages_out[0]["start_date"])
    available = days_inclusive(schedule_start, deadline)
    required = sum(s["duration_days"] for s in stages_out)
    buffer_days = (deadline - prev_end).days
    idle_gaps = available - required - buffer_days

    # ----- risk: take the model's view, but never let it be LOWER than what
    #       the numbers themselves say. -----
    warnings = list(context.get("warnings") or [])
    squeezed = [s["name"] for s in stages_out if s["duration_days"] < s["min_days"]]
    below_typical = sum(1 for s in stages_out if s["duration_days"] < s["typical_days"])
    floor = "LOW"
    if squeezed:
        floor = "HIGH"
    elif buffer_days == 0 or below_typical >= max(1, len(stages_out) // 2):
        floor = "MEDIUM"
    claimed = str(proposed.get("risk") or "").strip().upper()
    if claimed not in RISK_LEVELS:
        if source == "ai":
            warnings.append("The AI didn't give a valid risk level, so it was calculated from the dates.")
        claimed = floor
    risk = claimed if RISK_LEVELS.index(claimed) >= RISK_LEVELS.index(floor) else floor
    if risk != claimed:
        if squeezed:
            why = "too little time for " + ", ".join(squeezed)
        elif buffer_days == 0:
            why = "no buffer days before the final deadline"
        else:
            why = "%d of %d phases are shorter than usual" % (below_typical, len(stages_out))
        warnings.append("Risk raised from %s to %s based on the dates (%s)." % (claimed.title(), risk.title(), why))
    if squeezed:
        warnings.append("Below the usual minimum time: " + ", ".join(squeezed) + ".")
    if idle_gaps > 0:
        warnings.append("%d idle day(s) between phases — check that's intended." % idle_gaps)

    for w in (proposed.get("warnings") or [])[:5] if isinstance(proposed.get("warnings"), list) else []:
        w = _clean_text(w, MAX_WARNING_CHARS)
        if w and w not in warnings:
            warnings.append(w)

    reason = _clean_text(proposed.get("reason"), MAX_REASON_CHARS)
    if not reason:
        reason = ("Schedule edited by the manager." if source == "manager"
                  else "The AI didn't include an explanation.")

    return {
        "available_days": available,
        "required_days": required,
        "buffer_days": buffer_days,
        "idle_days": max(0, idle_gaps),
        "risk": risk,
        "reason": reason,
        "warnings": warnings,
        "stages": stages_out,
        "schedule_start": schedule_start.isoformat(),
        "final_deadline": deadline.isoformat(),
    }


def generate(context, manager_note=""):
    """Full generate step: OpenAI -> parse -> dates -> validate. No database
    access. If the model's answer breaks a rule, it is told exactly what was
    wrong and gets ONE more try (within the overall time budget) before the
    manager sees an error."""
    started = time.monotonic()
    schema = response_schema([p["key"] for p in context["phases"]])
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": build_user_prompt(context, manager_note)}]
    _key, _model, per_call_timeout, _effort = _llm_settings()
    last_error = None
    for attempt in (1, 2):
        remaining = TOTAL_BUDGET_SECONDS - (time.monotonic() - started)
        if attempt == 2 and remaining < 20:
            break
        text = chat_completion(messages, schema, timeout=min(per_call_timeout, max(10.0, remaining)))
        try:
            raw = extract_json(text)
            proposal = durations_to_dates(context, raw)
            return validate_schedule(context, proposal, source="ai")
        except SchedulingError as e:
            if not e.retryable:
                raise
            last_error = e
            messages += [{"role": "assistant", "content": text or ""},
                         {"role": "user", "content": "That answer was rejected by the server: %s "
                          "Correct it and reply again with the complete JSON object." % (e.feedback or e.msg)}]
    msg = last_error.msg if last_error else "The AI didn't answer in time."
    if "Regenerate" not in msg:
        msg += " Click Regenerate to try again, or add instructions."
    raise SchedulingError(msg, 422)
