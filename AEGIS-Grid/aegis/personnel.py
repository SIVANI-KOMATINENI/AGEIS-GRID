"""
aegis/personnel.py
Personnel Authority Registry and Cryptographic Authorization Verification.

AEGIS GRID Runtime Security Layer.

Security Architecture & Prototype Trust Model Note:
---------------------------------------------------
This module implements Step 1 of the Personnel Authority Registry.
It establishes a strict two-stage security boundary:
  Gate 1: Cryptographic Identity Authentication (Who issued this instruction?)
  Gate 2: Fine-Grained Authorization & Policy Scoping (Are they authorized for this action?)

Prototype Trust Model:
  In this simulation environment, cryptographic authentication uses a simulated
  trusted signing authority (SimulatedSigningAuthority) with server-side private keys
  and HMAC-SHA256 digests over canonical action data.
  Verification secrets and signing keys are kept strictly segregated from
  attacker-controlled action payloads.
  In a full production deployment, this would interface with a Hardware Security
  Module (HSM), Public Key Infrastructure (X.509 / PKI), or hardware-bound
  authenticators (e.g. FIDO2 / WebAuthn).
"""

import hmac
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Set, Literal, List
from pydantic import BaseModel, Field

from agents.schemas import ProposedAction, AuthorizationEvidence, compute_action_digest


# ── Schemas & Records ─────────────────────────────────────────────────────────

class ParameterLimits(BaseModel):
    """Configurable parameter constraints for personnel operational scope."""
    max_load_reduction_kw: Optional[float] = Field(
        default=None,
        description="Maximum load reduction allowed in kilowatts.",
    )
    min_battery_soc_pct: Optional[float] = Field(
        default=None,
        description="Minimum allowable battery state of charge percentage floor.",
    )
    max_battery_temp_c: Optional[float] = Field(
        default=None,
        description="Maximum allowable battery temperature in Celsius.",
    )
    allow_component_disconnection: bool = Field(
        default=False,
        description="Whether personnel is authorized to isolate or disconnect components.",
    )
    custom_limits: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extensible custom parameter thresholds.",
    )


class PersonnelRecord(BaseModel):
    """
    Structured record representing authorized personnel within the microgrid operations team.
    
    Security Principle:
      Identity attributes (experience_years, designation) are strictly informational.
      Authority is governed strictly by explicit permissions, parameter limits,
      cryptographic credential validity, and co-approval requirements.
    """
    personnel_id: str = Field(..., description="Unique personnel identifier, e.g. PERS-001")
    name: str = Field(..., description="Full name of personnel")
    designation: str = Field(..., description="Job designation / role title")
    department: str = Field(..., description="Department or operating unit")
    experience_years: int = Field(..., ge=0, description="Years of professional experience")
    is_active: bool = Field(default=True, description="Active status; False indicates revoked credential")
    valid_from: datetime = Field(..., description="Start of credential validity period")
    valid_to: datetime = Field(..., description="End of credential validity period")
    permitted_actions: Set[str] = Field(default_factory=set, description="Set of permitted action types")
    permitted_targets: Set[str] = Field(default_factory=set, description="Set of permitted target components")
    parameter_limits: ParameterLimits = Field(default_factory=ParameterLimits, description="Configurable parameter limits")
    max_priority: Literal["LOW", "MEDIUM", "HIGH"] = Field(default="MEDIUM", description="Maximum action priority permitted")
    requires_co_approval_actions: Set[str] = Field(default_factory=set, description="Action types requiring co-signer approval")
    requires_co_approval_targets: Set[str] = Field(default_factory=set, description="Target components requiring co-signer approval")
    credential_ref: str = Field(default="", description="Unique credential identifier or cert serial")
    issuer: str = Field(default="AEGIS_GRID_CA", description="Authority issuing the credential")


class AuthorityVerificationResult(BaseModel):
    """Structured result returned by personnel authority verification."""
    is_authenticated: bool = Field(
        ...,
        description="True if identity existence, active status, validity window, and cryptographic signature verified.",
    )
    is_authorized: bool = Field(
        ...,
        description="True if authenticated operator has authorization for action, target, priority, parameters, and co-approval.",
    )
    status_code: str = Field(
        ...,
        description=(
            "Standardized status code: AUTH_OK, MISSING_CREDENTIAL, UNSUPPORTED_TOKEN_TYPE, "
            "TAMPERED_ACTION, UNKNOWN_PERSONNEL, REVOKED_CREDENTIAL, EXPIRED_CREDENTIAL, "
            "MISSING_SIGNATURE, INVALID_SIGNATURE, UNAUTHORIZED_ACTION, UNAUTHORIZED_TARGET, "
            "PRIORITY_EXCEEDED, PARAMETER_EXCEEDED, MISSING_CO_APPROVAL, INVALID_CO_SIGNER."
        ),
    )
    failure_reason: Optional[str] = Field(
        default=None,
        description="Detailed explanation of failure, or None if completely authorized.",
    )
    personnel_id: Optional[str] = Field(
        default=None,
        description="Personnel ID when identified, or None.",
    )
    role: Optional[str] = Field(
        default=None,
        description="Designation / role of personnel when identified, or None.",
    )
    co_signer_id: Optional[str] = Field(
        default=None,
        description="Co-signer personnel ID when co-approval was required and verified.",
    )


# ── Prototype Signing Authority ───────────────────────────────────────────────

class SimulatedSigningAuthority:
    """
    Trusted local signing authority for personnel simulation.
    
    Security Architecture:
      - Maintains a private key store mapping personnel_id -> secret_key.
      - Keys are held strictly server-side by the authority and are NEVER
        exposed in action payloads, database rows, or agent contexts.
      - Produces and verifies keyed HMAC-SHA256 signatures over canonical data:
        f"PERSONNEL_AUTH:{personnel_id}:{action_digest}:{issued_at}:{nonce}"
    """

    def __init__(self) -> None:
        self._private_keys: Dict[str, str] = {}

    def register_key(self, personnel_id: str, key: Optional[str] = None) -> str:
        """Registers or generates a private signing key for a personnel ID."""
        if not key:
            key = secrets.token_hex(32)
        self._private_keys[personnel_id] = key
        return key

    def has_key(self, personnel_id: str) -> bool:
        """Checks if a private signing key exists for a personnel ID."""
        return personnel_id in self._private_keys

    def sign_action(
        self,
        personnel_id: str,
        action: ProposedAction,
        issued_at: str,
        nonce: str,
    ) -> str:
        """
        Signs an action using the private key for the given personnel.
        Signature covers canonical personnel_id, action_digest, issued_at, and nonce.
        """
        if personnel_id not in self._private_keys:
            raise ValueError(f"No private key registered for personnel '{personnel_id}'")

        if not action.is_digest_valid():
            raise ValueError("Cannot sign action with invalid or tampered action_digest")

        canonical_payload = self._compute_canonical_payload(
            personnel_id=personnel_id,
            action_digest=action.action_digest,
            issued_at=issued_at,
            nonce=nonce,
            action_id=action.action_id,
        )
        key = self._private_keys[personnel_id].encode("utf-8")
        return hmac.new(key, canonical_payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_signature(
        self,
        personnel_id: str,
        action_digest: str,
        issued_at: str,
        nonce: str,
        signature: str,
        action_id: Optional[str] = None,
    ) -> bool:
        """Verifies a signature using the private key registered for the personnel."""
        if not signature or personnel_id not in self._private_keys:
            return False

        key = self._private_keys[personnel_id].encode("utf-8")
        canonical_payload = self._compute_canonical_payload(
            personnel_id=personnel_id,
            action_digest=action_digest,
            issued_at=issued_at,
            nonce=nonce,
            action_id=action_id,
        )
        expected_sig = hmac.new(key, canonical_payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(expected_sig, signature):
            return True

        # Fallback to legacy payload without action_id if signature was generated under legacy format
        if action_id:
            legacy_payload = self._compute_canonical_payload(
                personnel_id=personnel_id,
                action_digest=action_digest,
                issued_at=issued_at,
                nonce=nonce,
                action_id=None,
            )
            legacy_sig = hmac.new(key, legacy_payload.encode("utf-8"), hashlib.sha256).hexdigest()
            if hmac.compare_digest(legacy_sig, signature):
                return True

        return False

    def issue_evidence(
        self,
        personnel_id: str,
        action: ProposedAction,
        issued_at: Optional[str] = None,
        nonce: Optional[str] = None,
        co_signer_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AuthorizationEvidence:
        """
        Helper for generating valid AuthorizationEvidence for legitimate workflows/tests.
        """
        if issued_at is None:
            issued_at = datetime.now(timezone.utc).isoformat()
        if nonce is None:
            nonce = secrets.token_hex(16)

        sig = self.sign_action(personnel_id, action, issued_at, nonce)
        co_sig = None
        if co_signer_id:
            co_sig = self.sign_action(co_signer_id, action, issued_at, nonce)

        return AuthorizationEvidence(
            token_type="PERSONNEL_CREDENTIAL",
            personnel_id=personnel_id,
            signature=sig,
            issued_at=issued_at,
            nonce=nonce,
            co_signer_id=co_signer_id,
            co_signer_signature=co_sig,
            action_id=action.action_id,
            metadata=metadata or {},
        )

    @staticmethod
    def _compute_canonical_payload(
        personnel_id: str,
        action_digest: str,
        issued_at: str,
        nonce: str,
        action_id: Optional[str] = None,
    ) -> str:
        parts = [
            "PERSONNEL_AUTH",
            personnel_id.strip(),
            action_digest.strip(),
            issued_at.strip(),
            nonce.strip(),
        ]
        if action_id:
            parts.append(action_id.strip())
        return ":".join(parts)


# ── Personnel Authority Registry ──────────────────────────────────────────────

class PersonnelAuthorityRegistry:
    """
    In-memory registry managing personnel records and authority profiles.
    Permissions and limits remain dynamically configurable.
    """

    def __init__(
        self,
        records: Optional[Dict[str, PersonnelRecord]] = None,
        signing_authority: Optional[SimulatedSigningAuthority] = None,
    ) -> None:
        self._records: Dict[str, PersonnelRecord] = dict(records or {})
        self.signing_authority = signing_authority or SimulatedSigningAuthority()

    def get_personnel(self, personnel_id: str) -> Optional[PersonnelRecord]:
        """Retrieves personnel record by ID."""
        return self._records.get(personnel_id)

    def register_personnel(
        self,
        record: PersonnelRecord,
        private_key: Optional[str] = None,
    ) -> None:
        """Registers a new personnel record and optionally assigns a private signing key."""
        self._records[record.personnel_id] = record
        if private_key or not self.signing_authority.has_key(record.personnel_id):
            self.signing_authority.register_key(record.personnel_id, private_key)

    def update_permissions(
        self,
        personnel_id: str,
        permitted_actions: Optional[Set[str]] = None,
        permitted_targets: Optional[Set[str]] = None,
        parameter_limits: Optional[ParameterLimits] = None,
        max_priority: Optional[Literal["LOW", "MEDIUM", "HIGH"]] = None,
    ) -> bool:
        """Updates permissions dynamically for an existing record."""
        if personnel_id not in self._records:
            return False
        rec = self._records[personnel_id]
        updates: Dict[str, Any] = {}
        if permitted_actions is not None:
            updates["permitted_actions"] = permitted_actions
        if permitted_targets is not None:
            updates["permitted_targets"] = permitted_targets
        if parameter_limits is not None:
            updates["parameter_limits"] = parameter_limits
        if max_priority is not None:
            updates["max_priority"] = max_priority
        self._records[personnel_id] = rec.model_copy(update=updates)
        return True

    def revoke_personnel(self, personnel_id: str) -> bool:
        """Revokes a personnel credential by setting is_active=False."""
        if personnel_id not in self._records:
            return False
        rec = self._records[personnel_id]
        self._records[personnel_id] = rec.model_copy(update={"is_active": False})
        return True

    def list_personnel_ids(self) -> List[str]:
        """Returns all registered personnel IDs."""
        return list(self._records.keys())


# ── Default Registry Fixtures (PERS-001 through PERS-005) ─────────────────────

def build_default_registry() -> PersonnelAuthorityRegistry:
    """
    Constructs the standard simulated personnel authority registry.
    Contains fictional personnel PERS-001 through PERS-005 with distinct authority scopes.
    """
    signing_auth = SimulatedSigningAuthority()

    # PERS-001: Elena Vance - Lead Grid Dispatcher (Active, High priority, max 250 kW)
    pers_001 = PersonnelRecord(
        personnel_id="PERS-001",
        name="Elena Vance",
        designation="Lead Grid Dispatcher",
        department="Grid Operations",
        experience_years=12,
        is_active=True,
        valid_from=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_to=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        permitted_actions={"SHUTDOWN_LOAD", "REDUCE_LOAD", "MAINTAIN_STATUS", "INSPECT", "LOG_WARNING", "INVESTIGATE"},
        permitted_targets={"load_1", "battery_1", "none"},
        parameter_limits=ParameterLimits(max_load_reduction_kw=250.0),
        max_priority="HIGH",
        requires_co_approval_actions=set(),
        requires_co_approval_targets=set(),
        credential_ref="cred_pers_001_v1",
        issuer="AEGIS_GRID_CA",
    )

    # PERS-002: Marcus Thorne - Junior Field Technician (Active, Inspection/investigation only)
    pers_002 = PersonnelRecord(
        personnel_id="PERS-002",
        name="Marcus Thorne",
        designation="Junior Field Technician",
        department="Field Maintenance",
        experience_years=2,
        is_active=True,
        valid_from=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_to=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        permitted_actions={"INSPECT", "LOG_WARNING", "INVESTIGATE", "MAINTAIN_STATUS"},
        permitted_targets={"battery_1", "load_1", "critical_load", "none"},
        parameter_limits=ParameterLimits(),
        max_priority="MEDIUM",
        requires_co_approval_actions=set(),
        requires_co_approval_targets=set(),
        credential_ref="cred_pers_002_v1",
        issuer="AEGIS_GRID_CA",
    )

    # PERS-003: Aria Patel - Battery Storage Engineer (Active, Storage control, max 50 kW)
    pers_003 = PersonnelRecord(
        personnel_id="PERS-003",
        name="Aria Patel",
        designation="Battery Storage Engineer",
        department="Energy Storage Systems",
        experience_years=7,
        is_active=True,
        valid_from=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_to=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        permitted_actions={"REDUCE_LOAD", "MAINTAIN_STATUS", "INSPECT", "LOG_WARNING", "INVESTIGATE"},
        permitted_targets={"battery_1", "load_1", "none"},
        parameter_limits=ParameterLimits(max_load_reduction_kw=50.0, allow_component_disconnection=False),
        max_priority="MEDIUM",
        requires_co_approval_actions=set(),
        requires_co_approval_targets=set(),
        credential_ref="cred_pers_003_v1",
        issuer="AEGIS_GRID_CA",
    )

    # PERS-004: Silas Vance - Operations Supervisor (Active, Full control, requires co-approval for critical)
    pers_004 = PersonnelRecord(
        personnel_id="PERS-004",
        name="Silas Vance",
        designation="Operations Supervisor",
        department="Grid Operations",
        experience_years=18,
        is_active=True,
        valid_from=datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_to=datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        permitted_actions={
            "ISOLATE_BATTERY",
            "REDUCE_LOAD",
            "SHUTDOWN_LOAD",
            "MAINTAIN_STATUS",
            "INSPECT",
            "LOG_WARNING",
            "INVESTIGATE",
        },
        permitted_targets={"battery_1", "critical_load", "load_1", "none"},
        parameter_limits=ParameterLimits(max_load_reduction_kw=500.0, allow_component_disconnection=True),
        max_priority="HIGH",
        requires_co_approval_actions={"SHUTDOWN_LOAD"},
        requires_co_approval_targets={"critical_load"},
        credential_ref="cred_pers_004_v1",
        issuer="AEGIS_GRID_CA",
    )

    # PERS-005: Devon Reed - Former Analyst (Revoked, Expired)
    pers_005 = PersonnelRecord(
        personnel_id="PERS-005",
        name="Devon Reed",
        designation="Former Analyst",
        department="System Planning",
        experience_years=5,
        is_active=False,
        valid_from=datetime(2025, 1, 1, 0, 0, 0, tzinfo=timezone.utc),
        valid_to=datetime(2025, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        permitted_actions={"INSPECT", "LOG_WARNING"},
        permitted_targets={"none"},
        parameter_limits=ParameterLimits(),
        max_priority="LOW",
        requires_co_approval_actions=set(),
        requires_co_approval_targets=set(),
        credential_ref="cred_pers_005_v1",
        issuer="AEGIS_GRID_CA",
    )

    registry = PersonnelAuthorityRegistry(
        records={
            "PERS-001": pers_001,
            "PERS-002": pers_002,
            "PERS-003": pers_003,
            "PERS-004": pers_004,
            "PERS-005": pers_005,
        },
        signing_authority=signing_auth,
    )

    # Deterministic keys for default personnel
    for pid in ["PERS-001", "PERS-002", "PERS-003", "PERS-004", "PERS-005"]:
        signing_auth.register_key(pid, f"sim_secret_key_{pid.lower()}")

    return registry


# ── Verification Core ─────────────────────────────────────────────────────────

PRIORITY_RANK = {
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
}


def verify_personnel_authority(
    action: ProposedAction,
    registry: Optional[PersonnelAuthorityRegistry] = None,
    now: Optional[datetime] = None,
    signing_authority: Optional[SimulatedSigningAuthority] = None,
) -> AuthorityVerificationResult:
    """
    Verifies that a proposed action is both cryptographically authenticated
    and within the fine-grained operational authority of the claimed personnel.
    
    Returns AuthorityVerificationResult with:
      - is_authenticated: True if cryptographic identity and validity window pass.
      - is_authorized: True if authenticated personnel has permission for this action scope.
      - status_code: Machine-readable status code.
      - failure_reason: Human-readable failure explanation.
      - personnel_id, role, co_signer_id.
    """
    # 1. Normalize evaluation time
    if now is None:
        now = datetime.now(timezone.utc)
    elif now.tzinfo is None:
        now = now.replace(tzinfo=timezone.utc)

    # 2. Resolve registry and signing authority
    if registry is None:
        registry = build_default_registry()
    if signing_authority is None:
        signing_authority = registry.signing_authority

    # 3. Check authorization evidence presence
    evidence = action.authorization_evidence
    if evidence is None:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="MISSING_CREDENTIAL",
            failure_reason="No authorization evidence attached to action proposal.",
        )

    # 4. Check token type
    if evidence.token_type != "PERSONNEL_CREDENTIAL":
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="UNSUPPORTED_TOKEN_TYPE",
            failure_reason=(
                f"Evidence token_type '{evidence.token_type}' is not supported for "
                "personnel authority verification."
            ),
            personnel_id=evidence.personnel_id,
        )

    # 5. Check personnel ID presence
    if not evidence.personnel_id:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="MISSING_CREDENTIAL",
            failure_reason="Missing personnel_id in authorization evidence.",
        )

    # 6. Check action payload integrity (action digest recomputed from current action)
    computed_digest = compute_action_digest(action.action_type, action.target, action.parameters)
    if not action.is_digest_valid() or (action.action_digest and action.action_digest != computed_digest):
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="TAMPERED_ACTION",
            failure_reason="Action digest does not match action payload contents (content tampered).",
            personnel_id=evidence.personnel_id,
        )

    # 6b. Check action context binding (action_id match against evidence)
    if evidence.action_id and action.action_id and evidence.action_id != action.action_id:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="TAMPERED_ACTION",
            failure_reason=(
                f"Action ID '{action.action_id}' does not match bound authorization evidence "
                f"action_id '{evidence.action_id}' (action context tampered)."
            ),
            personnel_id=evidence.personnel_id,
        )

    # 7. Check personnel existence in registry
    record = registry.get_personnel(evidence.personnel_id)
    if record is None:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="UNKNOWN_PERSONNEL",
            failure_reason=(
                f"Personnel ID '{evidence.personnel_id}' is not recognized in the "
                "authority registry."
            ),
            personnel_id=evidence.personnel_id,
        )

    personnel_id = record.personnel_id
    role = record.designation

    # 7b. Check single-use credential consumption in SQLite (reject replay)
    if evidence.nonce:
        from database.sqlite import is_personnel_credential_consumed
        db_path = getattr(registry, "db_path", None)
        kwargs = {"db_path": db_path} if db_path else {}
        if is_personnel_credential_consumed(personnel_id, evidence.nonce, **kwargs):
            return AuthorityVerificationResult(
                is_authenticated=False,
                is_authorized=False,
                status_code="CREDENTIAL_REUSED",
                failure_reason=(
                    f"Personnel authorization evidence (nonce '{evidence.nonce}') for "
                    f"{record.name} ({personnel_id}) has already been consumed (replay rejected)."
                ),
                personnel_id=personnel_id,
                role=role,
            )
        if evidence.co_signer_id and is_personnel_credential_consumed(evidence.co_signer_id, evidence.nonce, **kwargs):
            return AuthorityVerificationResult(
                is_authenticated=False,
                is_authorized=False,
                status_code="CREDENTIAL_REUSED",
                failure_reason=(
                    f"Co-signer authorization evidence (nonce '{evidence.nonce}') for "
                    f"co-signer '{evidence.co_signer_id}' has already been consumed (replay rejected)."
                ),
                personnel_id=personnel_id,
                role=role,
                co_signer_id=evidence.co_signer_id,
            )

    # 8. Check active / revocation status
    if not record.is_active:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="REVOKED_CREDENTIAL",
            failure_reason=(
                f"Personnel credential for {record.name} ({personnel_id}) has been "
                "revoked or deactivated."
            ),
            personnel_id=personnel_id,
            role=role,
        )

    # 9. Check validity period
    vf = record.valid_from if record.valid_from.tzinfo else record.valid_from.replace(tzinfo=timezone.utc)
    vt = record.valid_to if record.valid_to.tzinfo else record.valid_to.replace(tzinfo=timezone.utc)
    if now < vf or now > vt:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="EXPIRED_CREDENTIAL",
            failure_reason=(
                f"Personnel credential for {record.name} ({personnel_id}) is not valid "
                f"at evaluation time {now.isoformat()} (valid: {vf.isoformat()} to {vt.isoformat()})."
            ),
            personnel_id=personnel_id,
            role=role,
        )

    # 10. Check cryptographic signature presence
    if not evidence.signature:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="MISSING_SIGNATURE",
            failure_reason=f"Missing cryptographic signature for {record.name} ({personnel_id}).",
            personnel_id=personnel_id,
            role=role,
        )

    # 11. Verify cryptographic signature against trusted signing authority
    is_valid_sig = signing_authority.verify_signature(
        personnel_id=personnel_id,
        action_digest=computed_digest,
        issued_at=evidence.issued_at or "",
        nonce=evidence.nonce or "",
        signature=evidence.signature,
        action_id=action.action_id,
    )
    if not is_valid_sig:
        return AuthorityVerificationResult(
            is_authenticated=False,
            is_authorized=False,
            status_code="INVALID_SIGNATURE",
            failure_reason=f"Cryptographic signature verification failed for {record.name} ({personnel_id}).",
            personnel_id=personnel_id,
            role=role,
        )

    # ── GATE 1 PASSED: Identity Authenticated ────────────────────────────────
    # Any subsequent check failure represents an authorization scope violation.

    # 12. Check permitted actions
    if action.action_type not in record.permitted_actions:
        return AuthorityVerificationResult(
            is_authenticated=True,
            is_authorized=False,
            status_code="UNAUTHORIZED_ACTION",
            failure_reason=(
                f"Action type '{action.action_type}' is outside permitted actions for "
                f"{role} {record.name}."
            ),
            personnel_id=personnel_id,
            role=role,
        )

    # 13. Check permitted targets
    if action.target not in record.permitted_targets:
        return AuthorityVerificationResult(
            is_authenticated=True,
            is_authorized=False,
            status_code="UNAUTHORIZED_TARGET",
            failure_reason=(
                f"Target component '{action.target}' is outside permitted targets for "
                f"{role} {record.name}."
            ),
            personnel_id=personnel_id,
            role=role,
        )

    # 14. Check priority ceiling
    action_rank = PRIORITY_RANK.get(action.priority, 99)
    max_rank = PRIORITY_RANK.get(record.max_priority, 0)
    if action_rank > max_rank:
        return AuthorityVerificationResult(
            is_authenticated=True,
            is_authorized=False,
            status_code="PRIORITY_EXCEEDED",
            failure_reason=(
                f"Action priority '{action.priority}' exceeds maximum authorized priority "
                f"'{record.max_priority}' for {role} {record.name}."
            ),
            personnel_id=personnel_id,
            role=role,
        )

    # 15. Check parameter limits
    # 15a. Load reduction kilowatt limits
    reduction_kw = (
        action.parameters.get("reduction_kw")
        if action.parameters.get("reduction_kw") is not None
        else action.parameters.get("amount_kw")
    )
    if reduction_kw is not None:
        try:
            val_kw = float(reduction_kw)
            if val_kw <= 0:
                return AuthorityVerificationResult(
                    is_authenticated=True,
                    is_authorized=False,
                    status_code="PARAMETER_EXCEEDED",
                    failure_reason="Load reduction amount must be positive.",
                    personnel_id=personnel_id,
                    role=role,
                )
            if (
                record.parameter_limits.max_load_reduction_kw is not None
                and val_kw > record.parameter_limits.max_load_reduction_kw
            ):
                return AuthorityVerificationResult(
                    is_authenticated=True,
                    is_authorized=False,
                    status_code="PARAMETER_EXCEEDED",
                    failure_reason=(
                        f"Load reduction {val_kw} kW exceeds authorized limit of "
                        f"{record.parameter_limits.max_load_reduction_kw} kW for {role} {record.name}."
                    ),
                    personnel_id=personnel_id,
                    role=role,
                )
        except (ValueError, TypeError):
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="PARAMETER_EXCEEDED",
                failure_reason=f"Invalid numeric load reduction value: {reduction_kw}",
                personnel_id=personnel_id,
                role=role,
            )

    # 15b. Component disconnection / isolation authority
    if (
        action.action_type == "ISOLATE_BATTERY"
        or action.parameters.get("disconnect") is True
    ):
        if not record.parameter_limits.allow_component_disconnection:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="PARAMETER_EXCEEDED",
                failure_reason=(
                    f"Component disconnection/isolation is not authorized for "
                    f"{role} {record.name}."
                ),
                personnel_id=personnel_id,
                role=role,
            )

    # 15c. Minimum battery SoC floor
    target_soc = (
        action.parameters.get("target_soc")
        if action.parameters.get("target_soc") is not None
        else action.parameters.get("min_soc")
    )
    if target_soc is not None and record.parameter_limits.min_battery_soc_pct is not None:
        try:
            val_soc = float(target_soc)
            if val_soc < record.parameter_limits.min_battery_soc_pct:
                return AuthorityVerificationResult(
                    is_authenticated=True,
                    is_authorized=False,
                    status_code="PARAMETER_EXCEEDED",
                    failure_reason=(
                        f"Target battery SoC {val_soc}% is below authorized floor of "
                        f"{record.parameter_limits.min_battery_soc_pct}% for {role} {record.name}."
                    ),
                    personnel_id=personnel_id,
                    role=role,
                )
        except (ValueError, TypeError):
            pass

    # 15d. Maximum battery temperature ceiling
    max_temp = action.parameters.get("max_temp_c")
    if max_temp is not None and record.parameter_limits.max_battery_temp_c is not None:
        try:
            val_temp = float(max_temp)
            if val_temp > record.parameter_limits.max_battery_temp_c:
                return AuthorityVerificationResult(
                    is_authenticated=True,
                    is_authorized=False,
                    status_code="PARAMETER_EXCEEDED",
                    failure_reason=(
                        f"Battery temperature setpoint {val_temp}°C exceeds authorized ceiling of "
                        f"{record.parameter_limits.max_battery_temp_c}°C for {role} {record.name}."
                    ),
                    personnel_id=personnel_id,
                    role=role,
                )
        except (ValueError, TypeError):
            pass

    # 16. Dual-authorization / co-approval requirement check
    needs_co_approval = (
        action.action_type in record.requires_co_approval_actions
        or action.target in record.requires_co_approval_targets
    )
    if needs_co_approval:
        if not evidence.co_signer_id or not evidence.co_signer_signature:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="MISSING_CO_APPROVAL",
                failure_reason=(
                    f"Action '{action.action_type}' on '{action.target}' requires "
                    "dual-authorization (co-approval), but co-signer evidence is missing."
                ),
                personnel_id=personnel_id,
                role=role,
            )

        if evidence.co_signer_id == personnel_id:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason="Co-signer cannot be identical to the primary authorizing personnel.",
                personnel_id=personnel_id,
                role=role,
            )

        co_record = registry.get_personnel(evidence.co_signer_id)
        if co_record is None:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason=f"Co-signer ID '{evidence.co_signer_id}' is unknown in the registry.",
                personnel_id=personnel_id,
                role=role,
            )

        if not co_record.is_active:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason=(
                    f"Co-signer {co_record.name} ({co_record.personnel_id}) is inactive or revoked."
                ),
                personnel_id=personnel_id,
                role=role,
            )

        co_vf = co_record.valid_from if co_record.valid_from.tzinfo else co_record.valid_from.replace(tzinfo=timezone.utc)
        co_vt = co_record.valid_to if co_record.valid_to.tzinfo else co_record.valid_to.replace(tzinfo=timezone.utc)
        if now < co_vf or now > co_vt:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason=f"Co-signer credential for {co_record.name} is expired.",
                personnel_id=personnel_id,
                role=role,
            )

        # Co-approval verification: ensure second person is authorized for the action
        if action.action_type not in co_record.permitted_actions:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason=(
                    f"Co-signer {co_record.name} ({co_record.personnel_id}) is not authorized "
                    f"for action type '{action.action_type}'."
                ),
                personnel_id=personnel_id,
                role=role,
            )

        if action.target not in co_record.permitted_targets:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason=(
                    f"Co-signer {co_record.name} ({co_record.personnel_id}) is not authorized "
                    f"for target component '{action.target}'."
                ),
                personnel_id=personnel_id,
                role=role,
            )

        co_action_rank = PRIORITY_RANK.get(action.priority, 99)
        co_max_rank = PRIORITY_RANK.get(co_record.max_priority, 0)
        if co_action_rank > co_max_rank:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason=(
                    f"Action priority '{action.priority}' exceeds maximum authorized priority "
                    f"'{co_record.max_priority}' for co-signer {co_record.name}."
                ),
                personnel_id=personnel_id,
                role=role,
            )

        is_valid_co_sig = signing_authority.verify_signature(
            personnel_id=co_record.personnel_id,
            action_digest=computed_digest,
            issued_at=evidence.issued_at or "",
            nonce=evidence.nonce or "",
            signature=evidence.co_signer_signature,
            action_id=action.action_id,
        )
        if not is_valid_co_sig:
            return AuthorityVerificationResult(
                is_authenticated=True,
                is_authorized=False,
                status_code="INVALID_CO_SIGNER",
                failure_reason=f"Cryptographic signature verification failed for co-signer {co_record.name}.",
                personnel_id=personnel_id,
                role=role,
            )

    # ── GATE 2 PASSED: Authorization Scope Verified ──────────────────────────
    return AuthorityVerificationResult(
        is_authenticated=True,
        is_authorized=True,
        status_code="AUTH_OK",
        failure_reason=None,
        personnel_id=personnel_id,
        role=role,
        co_signer_id=evidence.co_signer_id if needs_co_approval else None,
    )
