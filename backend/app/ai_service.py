"""
AI photo triage for CivicTrace, using Google's Interactions API
(the current recommended Gemini API surface, replacing the older
generateContent REST endpoint).
"""

import base64
import json
import math
import traceback
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

INTERACTIONS_URL = "https://generativelanguage.googleapis.com/v1beta/interactions"

# Structured output schema -- Gemini is instructed to return JSON that
# matches this exactly, instead of us hoping it follows a plain-text
# prompt instruction. Much more reliable than free-form parsing.
RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "is_civic_issue": {"type": "boolean"},
        "detected_category": {
            "type": "string",
            "enum": VALID_CATEGORIES
        },
        "category_match": {"type": "boolean"},
        "confidence": {"type": "number"},
        "severity_score": {"type": "integer"},
        "reasoning": {"type": "string"}
    },
    "required": [
        "is_civic_issue",
        "detected_category",
        "category_match",
        "confidence",
        "severity_score",
        "reasoning"
    ]
}


def _prompt(category: str, description: Optional[str]) -> str:
    return (
        "You are a municipal civic-issue triage assistant for CivicTrace, "
        "a public infrastructure reporting platform.\n\n"
        f'A citizen submitted a photo claiming it shows a "{category}" civic '
        f'issue, with this description: "{description or "(no description provided)"}"\n\n'
        "Judge: (1) is_civic_issue -- false if the photo shows nothing resembling "
        "a real public-infrastructure problem (selfies, memes, unrelated objects); "
        "(2) detected_category -- your best guess at what it actually shows; "
        "(3) category_match -- true only if detected_category reasonably matches "
        f'the claimed category "{category}"; (4) severity_score 1-100, visual '
        "severity only, based on size/scale in frame, depth or structural damage, "
        "standing water, exposed hazards (rebar, live wires), whether it blocks a "
        "path/road, and danger to pedestrians/vehicles "
        "(1-20 cosmetic, 21-50 moderate, 51-75 serious, 76-100 severe/urgent); "
        "(5) reasoning -- one or two sentences explaining the severity_score."
    )


def _extract_output_text(data: Dict[str, Any]) -> Optional[str]:
    """
    The Interactions API response shape can expose the final text either
    as a convenience field or nested inside the steps array, depending
    on API revision. Try both rather than assuming one.
    """

    if data.get("output_text"):
        return data["output_text"]

    for step in data.get("steps", []):
        if step.get("type") != "model_output":
            continue
        for block in step.get("content", []):
            if block.get("type") == "text" and block.get("text"):
                return block["text"]

    return None


def analyze_evidence_image(
    image_bytes: bytes,
    mime_type: str,
    category: str,
    description: Optional[str] = None
) -> Optional[Dict[str, Any]]:

    api_key = settings.GEMINI_API_KEY

    if not api_key:
        print("[ai_service] GEMINI_API_KEY is not set -- skipping AI analysis.")
        return None

    image_b64 = base64.b64encode(image_bytes).decode("utf-8")

    payload = {
        "model": settings.GEMINI_MODEL,
        "input": [
            {"type": "text", "text": _prompt(category, description)},
            {"type": "image", "data": image_b64, "mime_type": mime_type}
        ],
        "response_format": {
            "type": "text",
            "mime_type": "application/json",
            "schema": RESPONSE_SCHEMA
        }
    }

    headers = {
        "x-goog-api-key": api_key,
        "Content-Type": "application/json",
        "Api-Revision": "2026-05-20"
    }

    try:
        response = httpx.post(
            INTERACTIONS_URL,
            headers=headers,
            json=payload,
            timeout=30.0
        )

        if response.status_code >= 400:
            print(
                f"[ai_service] Gemini Interactions API returned "
                f"{response.status_code}: {response.text}"
            )
            return None

        data = response.json()

        text = _extract_output_text(data)

        if not text:
            # We reached Gemini fine but the response shape wasn't what
            # we expected -- print the raw JSON so we can see the real
            # structure and fix parsing in one precise edit next time.
            print(
                "[ai_service] Could not find output text in Gemini response. "
                f"Raw response: {json.dumps(data)[:2000]}"
            )
            return None

        result = json.loads(text)

        result["severity_score"] = max(1, min(100, int(result.get("severity_score", 50))))
        result["confidence"] = max(0.0, min(1.0, float(result.get("confidence", 0.5))))
        result["is_civic_issue"] = bool(result.get("is_civic_issue", True))
        result["category_match"] = bool(result.get("category_match", True))
        result["detected_category"] = str(result.get("detected_category", category))
        result["reasoning"] = str(result.get("reasoning", ""))[:500]

        return result

    except Exception:
        print("[ai_service] Gemini analysis failed:")
        traceback.print_exc()
        return None


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    earth_radius_km = 6371.0
    phi1, phi2 = math.radians(lat1), math.radians(lat2)
    d_phi = math.radians(lat2 - lat1)
    d_lambda = math.radians(lon2 - lon1)
    a = math.sin(d_phi / 2) ** 2 + math.cos(phi1) * math.cos(phi2) * math.sin(d_lambda / 2) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
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
        distance_km = _haversine_km(latitude, longitude, c.latitude, c.longitude)
        if distance_km <= radius_km:
            nearby_count += 1

    return min(nearby_count * 15, 100)


def combine_risk_score(
    ai_result: Optional[Dict[str, Any]],
    hotspot_score: int
) -> int:
    if ai_result is None:
        return max(30, hotspot_score)
    severity = ai_result["severity_score"]
    return round((0.65 * severity) + (0.35 * hotspot_score))


def mime_type_for_extension(extension: str) -> str:
    return {
        ".png": "image/png",
        ".webp": "image/webp",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg"
    }.get(extension, "image/jpeg")