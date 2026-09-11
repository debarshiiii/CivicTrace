"""
AI photo triage for CivicTrace.

Two separate, deliberately different mechanisms:

1. analyze_evidence_image() -- calls Google's Gemini API (vision-capable,
   free tier available) to look at a citizen's uploaded photo and judge
   whether it actually shows the claimed civic issue, plus a visual
   severity score. This is genuinely something only a vision model can do.

2. compute_hotspot_score() -- NOT an AI call. "Usual hotspots of the city"
   just means: how many other reports of this same issue type already
   exist near this location? That's a plain distance query over
   CivicTrace's own case history. No model can know a city's actual
   pothole hotspots better than CivicTrace's own accumulated reports do,
   so this stays deterministic, fast, and free.

combine_risk_score() blends the two into the single risk_score used for
sorting/prioritizing cases.

IMPORTANT: analyze_evidence_image() never raises. If the API key is
missing, the network call fails, or the model returns something
unparseable, it returns None. Callers must treat None as "AI review
unavailable right now" and fall back gracefully -- an AI hiccup must
never block or hide a citizen's report.

Auth note: Google's current guidance (2026) is to send the API key via
the `x-goog-api-key` header rather than a `?key=` query parameter, since
query params can leak into server/proxy access logs. That's what this
module does.
"""

import base64
import json
import math
import re
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from .config import settings
from .models import Case


VALID_CATEGORIES = [
    "pothole",
    "garbage",
    "water_leak",
    "streetlight",
    "unsafe_area",
    "other",
]


ANALYSIS_PROMPT = """
You are a municipal civic-issue triage assistant for CivicTrace, a public
infrastructure reporting platform.

A citizen submitted a photo claiming it shows a "{category}" civic issue,
with this description: "{description}"

Look at the photo and respond with ONLY a single JSON object (no markdown
fences, no extra commentary) with exactly these fields:

{{
  "is_civic_issue": true or false,
  "detected_category": one of {categories},
  "category_match": true or false,
  "confidence": a number from 0 to 1,
  "severity_score": an integer from 1 to 100,
  "reasoning": a one or two sentence explanation
}}

Field notes:
- is_civic_issue: false if the photo shows nothing resembling a real
  public-infrastructure problem (selfies, memes, unrelated objects, etc).
- detected_category: your best guess at what the photo actually shows,
  regardless of what the citizen claimed.
- category_match: true only if detected_category reasonably matches the
  claimed category "{category}".
- severity_score: visual severity ONLY, based on size/scale visible in
  frame, apparent depth or structural damage, standing water, exposed
  hazards (rebar, live wires), whether it blocks a path or road, and
  immediate danger to pedestrians/vehicles.
  1-20 = cosmetic/minor, 21-50 = moderate, 51-75 = serious,
  76-100 = severe/urgent hazard.

Return ONLY the JSON object, nothing else.
"""


def _extract_json(text: str) -> Dict[str, Any]:

    cleaned = text.strip()
    cleaned = re.sub(r"^```(json)?", "", cleaned, flags=re.I).strip()
    cleaned = re.sub(r"```$", "", cleaned).strip()

    return json.loads(cleaned)


def analyze_evidence_image(
    image_bytes: bytes,
    mime_type: str,
    category: str,
    description: Optional[str] = None
) -> Optional[Dict[str, Any]]:

    api_key = settings.GEMINI_API_KEY

    if not api_key:
        return None

    prompt = ANALYSIS_PROMPT.format(
        category=category,
        description=description or "(no description provided)",
        categories=VALID_CATEGORIES
    )

    image_b64 = base64.b64encode(image_bytes).decode("utf-8")

    url = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{settings.GEMINI_MODEL}:generateContent"
    )

    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt},
                    {
                        "inline_data": {
                            "mime_type": mime_type,
                            "data": image_b64
                        }
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.1,
            "response_mime_type": "application/json"
        }
    }

    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json"
    }

    try:

        response = httpx.post(
            url,
            headers=headers,
            json=payload,
            timeout=20.0
        )

        response.raise_for_status()

        data = response.json()

        text = data["candidates"][0]["content"]["parts"][0]["text"]

        result = _extract_json(text)

        # Don't trust the model's shape blindly -- clamp/coerce everything.
        result["severity_score"] = max(
            1,
            min(100, int(result.get("severity_score", 50)))
        )

        result["confidence"] = max(
            0.0,
            min(1.0, float(result.get("confidence", 0.5)))
        )

        result["is_civic_issue"] = bool(
            result.get("is_civic_issue", True)
        )

        result["category_match"] = bool(
            result.get("category_match", True)
        )

        result["detected_category"] = str(
            result.get("detected_category", category)
        )

        result["reasoning"] = str(
            result.get("reasoning", "")
        )[:500]

        return result

    except Exception as exc:

        # Never let an AI/network hiccup block a citizen's report.
        print(f"[ai_service] Gemini analysis failed: {exc}")
        return None


def _haversine_km(
    lat1: float,
    lon1: float,
    lat2: float,
    lon2: float
) -> float:

    earth_radius_km = 6371.0

    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)

    a = (
        math.sin(d_phi / 2) ** 2
        + math.cos(phi1)
        * math.cos(phi2)
        * math.sin(d_lambda / 2) ** 2
    )

    c = 2 * math.atan2(
        math.sqrt(a),
        math.sqrt(1 - a)
    )

    return earth_radius_km * c


def compute_hotspot_score(
    db: Session,
    category: str,
    latitude: Optional[float],
    longitude: Optional[float],
    radius_km: float = 0.3,
    exclude_case_id: Optional[str] = None
) -> int:

    if latitude is None or longitude is None:
        return 0

    query = (
        db.query(Case)
        .filter(Case.category == category)
        .filter(Case.latitude.isnot(None))
        .filter(Case.longitude.isnot(None))
    )

    if exclude_case_id:
        query = query.filter(Case.id != exclude_case_id)

    candidates = query.all()

    nearby_count = 0

    for c in candidates:

        distance_km = _haversine_km(
            latitude,
            longitude,
            c.latitude,
            c.longitude
        )

        if distance_km <= radius_km:
            nearby_count += 1

    # Each nearby prior report of the same issue type bumps the score.
    return min(nearby_count * 15, 100)


def combine_risk_score(
    ai_result: Optional[Dict[str, Any]],
    hotspot_score: int
) -> int:

    if ai_result is None:
        # Can't assess visual severity -- don't hide the case either.
        return max(30, hotspot_score)

    severity = ai_result["severity_score"]

    return round(
        (0.65 * severity)
        + (0.35 * hotspot_score)
    )


def mime_type_for_extension(extension: str) -> str:

    return {
        ".png": "image/png",
        ".webp": "image/webp",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg"
    }.get(extension, "image/jpeg")