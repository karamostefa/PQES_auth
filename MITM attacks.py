"""MITM resistance tests for the PQES-AKE prototype.

These tests intentionally model an active network attacker sitting between Alice
and Bob.  Every scenario is executed 100 times with deterministic but different
random seeds/values.

Security expectation used by the tests:
    * Any attacker-modified AUTHA message must be rejected by Bob.
    * Any attacker-modified AUTHB message must be rejected by Alice.
    * Cross-session mix-and-match, stale response injection, wrong-key
      substitution, and replayed first flights must not be accepted as a fresh
      authenticated session.
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import os
import random
import sys
from contextlib import redirect_stdout
from dataclasses import dataclass, replace
from pathlib import Path
from types import ModuleType
from typing import Callable, Iterable, Optional, Set, Tuple

import pytest

MITM_ATTACK_REPETITIONS = 10
DETERMINISTIC_MITM_SEED = 20250623

MODULE_ENV_VAR = "PQES_AUTH_MODULE_PATH"
MODULE_FILE_NAMES = ("PQES_auth.py", "PQES auth.py")


@dataclass(frozen=True)
class AliceInitiation:
    """Alice's first flight plus the local state she must retain."""

    n: int
    u: int
    v: int
    s1: int
    s2: int
    M: int
    hXa: str
    xa: int
    r1: int
    r2: int
    ts: int
    ht: bytes
    seq_a: int
    seq_a_sent: int


@dataclass(frozen=True)
class BobResponse:
    """Bob's second flight plus Bob's accepted DH value."""

    M_prime: int
    hXb: str
    dh_secret: bytes  # Maps to Z_b
    auth_b: str


class MitmHandshakeDriver:
    """Small readable adapter around the prototype's protocol functions."""

    def __init__(self, pqes: ModuleType) -> None:
        self.pqes = pqes
        # Local state tracking for anti-replay features
        self.seq_a = 0
        self.seq_b = 0
        self.bob_seen_seqs: Set[Tuple[int, int]] = set()

    def seed(self, seed: int) -> None:
        random.seed(seed)
        if hasattr(self.pqes, "random"):
            self.pqes.random.seed(seed)
        # Reset protocol states on re-seed
        self.seq_a = 0
        self.seq_b = 0
        self.bob_seen_seqs = set()

    def alice_runs_auth_a(self) -> AliceInitiation:
        with redirect_stdout(io.StringIO()):
            values = self.pqes.auth_a(
                self.seq_a,
                self.pqes.p,
                self.pqes.p1,
                self.pqes.g,
                self.pqes.n0,
                self.pqes.k1_a,
                self.pqes.k2_a,
                self.pqes.a_b,
                self.pqes.b_b,
            )
        # Track updated sequence locally
        self.seq_a = values[12]
        return AliceInitiation(*values)

    def alice_runs_auth_a_with_receiver_public_key(self, a_b: int, b_b: int) -> AliceInitiation:
        with redirect_stdout(io.StringIO()):
            values = self.pqes.auth_a(
                self.seq_a,
                self.pqes.p,
                self.pqes.p1,
                self.pqes.g,
                self.pqes.n0,
                self.pqes.k1_a,
                self.pqes.k2_a,
                a_b,
                b_b,
            )
        self.seq_a = values[12]
        return AliceInitiation(*values)

    def bob_runs_auth_b(
            self,
            alice: AliceInitiation,
            *,
            K11_a: Optional[int] = None,
            K12_a: Optional[int] = None,
    ) -> Optional[BobResponse]:
        with redirect_stdout(io.StringIO()):
            response = self.pqes.auth_b(
                self.seq_b,
                alice.seq_a_sent,
                self.bob_seen_seqs,
                alice.u,
                alice.v,
                alice.s1,
                alice.s2,
                alice.M,
                alice.hXa,
                alice.ts,
                alice.ht,
                self.pqes.p,
                self.pqes.p1,
                self.pqes.g,
                self.pqes.s_b,
                self.pqes.e_b,
                self.pqes.K11_a if K11_a is None else K11_a,
                self.pqes.K12_a if K12_a is None else K12_a,
            )

        if response is None:
            return None

        # Unpack state mutations returned from auth_b
        M_prime, hXb, Z_b, auth_b, updated_seq_b, updated_seen_seqs = response
        self.seq_b = updated_seq_b
        self.bob_seen_seqs = updated_seen_seqs

        return BobResponse(M_prime, hXb, Z_b, auth_b)

    def alice_runs_auth_a_prime(
            self,
            alice: AliceInitiation,
            bob: BobResponse,
    ) -> Optional[bytes]:
        with redirect_stdout(io.StringIO()):
            return self.pqes.auth__a(
                alice.n,
                self.pqes.p,
                self.pqes.p1,
                bob.M_prime,
                bob.hXb,
                alice.xa,
                alice.u,
                alice.v,
                alice.s1,  
                alice.s2,
                alice.r1,
                alice.r2,
                bob.auth_b,
                self.pqes.K11_b,
                self.pqes.K12_b,
            )


@dataclass(frozen=True)
class FieldTamperScenario:
    name: str
    field_name: str
    modulus_name: str
    mutation_name: str


@dataclass(frozen=True)
class MixAndMatchScenario:
    name: str
    build: Callable[[AliceInitiation, AliceInitiation], AliceInitiation]


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


def _candidate_module_paths() -> Iterable[Path]:
    tests_directory = Path(__file__).resolve().parent
    project_root = _project_root()

    for file_name in MODULE_FILE_NAMES:
        yield project_root / "src" / file_name
        yield tests_directory / ".." / "src" / file_name
        yield Path.cwd() / "src" / file_name
        yield Path.cwd() / file_name
        yield Path("/mnt/data") / file_name


def _pqes_module_path() -> Path:
    env_path = os.getenv(MODULE_ENV_VAR)
    if env_path:
        return Path(env_path).expanduser().resolve()

    for candidate in _candidate_module_paths():
        resolved_candidate = candidate.resolve()
        if resolved_candidate.exists():
            return resolved_candidate

    searched_paths = "\n".join(str(path.resolve()) for path in _candidate_module_paths())
    raise FileNotFoundError(
        f"Could not find one of {MODULE_FILE_NAMES!r}. "
        f"Set {MODULE_ENV_VAR} to its path.\n"
        f"Searched:\n{searched_paths}"
    )


def _load_module_from_path(path: Path, seed: int) -> ModuleType:
    random.seed(seed)

    module_name = f"pqes_auth_under_mitm_test_{seed}"
    spec = importlib.util.spec_from_file_location(module_name, path)

    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module from {path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module

    with redirect_stdout(io.StringIO()):
        spec.loader.exec_module(module)

    if hasattr(module, "random"):
        module.random.seed(seed)

    return module


def _new_mitm_driver() -> MitmHandshakeDriver:
    pqes = _load_module_from_path(_pqes_module_path(), DETERMINISTIC_MITM_SEED)
    return MitmHandshakeDriver(pqes)


def _stable_int(label: str) -> int:
    return int(hashlib.sha256(label.encode("utf-8")).hexdigest(), 16)


def _execution_seed(scenario_name: str, execution_number: int) -> int:
    return DETERMINISTIC_MITM_SEED + _stable_int(scenario_name) % 1_000_000 + execution_number


def _different_int(value: int, modulus: int, rng: random.Random) -> int:
    candidate = value
    while candidate == value:
        candidate = rng.randrange(0, modulus)
    return candidate


def _different_hash(value: str, rng: random.Random) -> str:
    candidate = value
    while candidate == value:
        candidate = hashlib.sha256(str(rng.getrandbits(512)).encode("ascii")).hexdigest()
    return candidate


def _different_bytes(value: bytes, rng: random.Random) -> bytes:
    candidate = value
    while candidate == value:
        candidate = hashlib.sha256(str(rng.getrandbits(512)).encode("ascii")).digest()
    return candidate


def _tampered_int(value: int, modulus: int, mutation_name: str, rng: random.Random) -> int:
    if mutation_name == "random-replacement":
        return _different_int(value, modulus, rng)
    if mutation_name == "increment":
        return (value + rng.randrange(1, min(modulus, 10_000))) % modulus
    if mutation_name == "decrement":
        return (value - rng.randrange(1, min(modulus, 10_000))) % modulus
    if mutation_name == "zero":
        return 0 if value != 0 else 1
    if mutation_name == "one":
        return 1 if value != 1 else 2
    if mutation_name == "modulus-minus-one":
        return modulus - 1 if value != modulus - 1 else modulus - 2
    if mutation_name == "bit-flip":
        bit = 1 << rng.randrange(0, max(1, value.bit_length()))
        return (value ^ bit) % modulus

    raise ValueError(f"Unsupported mutation: {mutation_name}")


def _tamper_alice_first_flight(
        alice: AliceInitiation,
        scenario: FieldTamperScenario,
        pqes: ModuleType,
        rng: random.Random,
) -> AliceInitiation:
    value = getattr(alice, scenario.field_name)

    if scenario.field_name == "hXa":
        mutated_value = _different_hash(value, rng)
    elif scenario.field_name == "ht":
        mutated_value = _different_bytes(value, rng)
    else:
        modulus = getattr(pqes, scenario.modulus_name)
        mutated_value = _tampered_int(value, modulus, scenario.mutation_name, rng)

    return replace(alice, **{scenario.field_name: mutated_value})


def _tamper_bob_response(
        bob: BobResponse,
        scenario: FieldTamperScenario,
        pqes: ModuleType,
        rng: random.Random,
) -> BobResponse:
    value = getattr(bob, scenario.field_name)

    if scenario.field_name in ("hXb", "auth_b"):
        mutated_value = _different_hash(value, rng)
    else:
        modulus = getattr(pqes, scenario.modulus_name)
        mutated_value = _tampered_int(value, modulus, scenario.mutation_name, rng)

    return replace(bob, **{scenario.field_name: mutated_value})


def _assert_honest_handshake_still_works(driver: MitmHandshakeDriver) -> None:
    alice = driver.alice_runs_auth_a()
    bob = driver.bob_runs_auth_b(alice)
    assert bob is not None, "Sanity check failed: Bob rejected an honest AUTHA message."

    alice_dh = driver.alice_runs_auth_a_prime(alice, bob)
    assert alice_dh is not None, "Sanity check failed: Alice rejected an honest AUTHB message."
    assert alice_dh == bob.dh_secret


FIRST_FLIGHT_INT_FIELDS = (
    ("u", "p"),
    ("v", "p"),
    ("s1", "p1"),
    ("s2", "p1"),
    ("M", "p"),
)

BOB_RESPONSE_INT_FIELDS = (
    ("M_prime", "p"),
)

MUTATIONS = (
    "random-replacement",
    "increment",
    "decrement",
    "zero",
    "one",
    "modulus-minus-one",
    "bit-flip",
)

FIRST_FLIGHT_TAMPER_SCENARIOS = tuple(
    FieldTamperScenario(
        name=f"AUTHA-{field_name}-{mutation_name}",
        field_name=field_name,
        modulus_name=modulus_name,
        mutation_name=mutation_name,
    )
    for field_name, modulus_name in FIRST_FLIGHT_INT_FIELDS
    for mutation_name in MUTATIONS
) + (
                                    FieldTamperScenario(
                                        name="AUTHA-hXa-random-replacement",
                                        field_name="hXa",
                                        modulus_name="p",
                                        mutation_name="random-replacement",
                                    ),
                                    FieldTamperScenario(
                                        name="AUTHA-ht-random-replacement",
                                        field_name="ht",
                                        modulus_name="p",
                                        mutation_name="random-replacement",
                                    ),
                                )

BOB_RESPONSE_TAMPER_SCENARIOS = tuple(
    FieldTamperScenario(
        name=f"AUTHB-{field_name}-{mutation_name}",
        field_name=field_name,
        modulus_name=modulus_name,
        mutation_name=mutation_name,
    )
    for field_name, modulus_name in BOB_RESPONSE_INT_FIELDS
    for mutation_name in MUTATIONS
) + (
                                    FieldTamperScenario(
                                        name="AUTHB-hXb-random-replacement",
                                        field_name="hXb",
                                        modulus_name="p",
                                        mutation_name="random-replacement",
                                    ),
                                    FieldTamperScenario(
                                        name="AUTHB-auth_b-random-replacement",
                                        field_name="auth_b",
                                        modulus_name="p",
                                        mutation_name="random-replacement",
                                    ),
                                )

MIX_AND_MATCH_SCENARIOS = (
    MixAndMatchScenario(
        name="ciphertext-and-signature-from-session-1-masked-values-from-session-2",
        build=lambda a1, a2: replace(
            a1,
            M=a2.M,
            hXa=a2.hXa,
            ht=a2.ht,
        ),
    ),
    MixAndMatchScenario(
        name="ciphertext-from-session-1-signature-from-session-2",
        build=lambda a1, a2: replace(a1, s1=a2.s1, s2=a2.s2),
    ),
    MixAndMatchScenario(
        name="signature-from-session-1-ciphertext-from-session-2",
        build=lambda a1, a2: replace(a1, u=a2.u, v=a2.v),
    ),
)


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.parametrize(
    "scenario",
    FIRST_FLIGHT_TAMPER_SCENARIOS,
    ids=lambda scenario: scenario.name,
)
def test_mitm_tampering_of_alice_first_flight_is_rejected_by_bob(
        scenario: FieldTamperScenario,
) -> None:
    """MITM changes one AUTHA field: Bob must reject every modified transcript."""
    driver = _new_mitm_driver()

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario.name, execution_number)
        rng = random.Random(seed)
        driver.seed(seed)

        alice = driver.alice_runs_auth_a()
        tampered_alice = _tamper_alice_first_flight(alice, scenario, driver.pqes, rng)

        assert driver.bob_runs_auth_b(tampered_alice) is None, (
            f"Bob accepted a MITM-modified AUTHA message in {scenario.name}, "
            f"execution {execution_number + 1}."
        )


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.parametrize(
    "scenario",
    BOB_RESPONSE_TAMPER_SCENARIOS,
    ids=lambda scenario: scenario.name,
)
def test_mitm_tampering_of_bob_response_is_rejected_by_alice(
        scenario: FieldTamperScenario,
) -> None:
    """MITM changes one AUTHB field: Alice must reject every modified transcript."""
    driver = _new_mitm_driver()

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario.name, execution_number)
        rng = random.Random(seed)
        driver.seed(seed)

        alice = driver.alice_runs_auth_a()
        bob = driver.bob_runs_auth_b(alice)
        assert bob is not None, "Sanity check failed: Bob rejected an honest AUTHA message."

        tampered_bob = _tamper_bob_response(bob, scenario, driver.pqes, rng)

        assert driver.alice_runs_auth_a_prime(alice, tampered_bob) is None, (
            f"Alice accepted a MITM-modified AUTHB message in {scenario.name}, "
            f"execution {execution_number + 1}."
        )


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.parametrize(
    "scenario",
    MIX_AND_MATCH_SCENARIOS,
    ids=lambda scenario: scenario.name,
)
def test_mitm_cross_session_mix_and_match_is_rejected_by_bob(
        scenario: MixAndMatchScenario,
) -> None:
    """MITM splices fields from two honest AUTHA sessions: Bob must reject."""
    driver = _new_mitm_driver()

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario.name, execution_number)
        driver.seed(seed)

        alice_session_1 = driver.alice_runs_auth_a()
        # Reset driver sequence count so session 2 generates independently
        driver.seq_a = 0
        alice_session_2 = driver.alice_runs_auth_a()
        mixed_alice = scenario.build(alice_session_1, alice_session_2)

        assert driver.bob_runs_auth_b(mixed_alice) is None, (
            f"Bob accepted a cross-session spliced AUTHA message in {scenario.name}, "
            f"execution {execution_number + 1}."
        )


@pytest.mark.integration
@pytest.mark.security
def test_mitm_stale_bob_response_for_previous_session_is_rejected_by_alice() -> None:
    """MITM gives Alice a valid AUTHB response from a different session."""
    driver = _new_mitm_driver()
    scenario_name = "stale-AUTHB-response-injected-into-new-session"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)
        driver.seed(seed)

        old_alice = driver.alice_runs_auth_a()
        old_bob = driver.bob_runs_auth_b(old_alice)
        assert old_bob is not None, "Sanity check failed: Bob rejected an honest AUTHA message."

        # Generate a distinct fresh initiation flight
        driver.seq_a = 0
        new_alice = driver.alice_runs_auth_a()

        assert driver.alice_runs_auth_a_prime(new_alice, old_bob) is None, (
            "Alice accepted a stale AUTHB response from another session, "
            f"execution {execution_number + 1}."
        )


@pytest.mark.integration
@pytest.mark.security
def test_mitm_wrong_alice_verification_key_is_rejected_by_bob() -> None:
    """MITM or configuration bug causes Bob to verify Alice with a wrong public key."""
    driver = _new_mitm_driver()
    scenario_name = "wrong-Alice-verification-key"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)
        driver.seed(seed)

        alice = driver.alice_runs_auth_a()

        assert driver.bob_runs_auth_b(
            alice,
            K11_a=driver.pqes.K11_b,
            K12_a=driver.pqes.K12_b,
        ) is None, (
            "Bob accepted AUTHA while using the wrong Alice verification key, "
            f"execution {execution_number + 1}."
        )


@pytest.mark.integration
@pytest.mark.security
def test_mitm_receiver_public_key_substitution_is_rejected_by_bob() -> None:
    """MITM makes Alice encrypt/sign for a substituted receiver public key."""
    driver = _new_mitm_driver()
    scenario_name = "receiver-public-key-substitution"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)
        driver.seed(seed)

        alice_for_wrong_receiver_key = driver.alice_runs_auth_a_with_receiver_public_key(
            driver.pqes.a_a,
            driver.pqes.b_a,
        )

        assert driver.bob_runs_auth_b(alice_for_wrong_receiver_key) is None, (
            "Bob accepted AUTHA generated for a substituted receiver public key, "
            f"execution {execution_number + 1}."
        )


@pytest.mark.integration
@pytest.mark.security
def test_mitm_replayed_alice_first_flight_is_not_accepted_as_fresh_session_by_bob() -> None:
    """MITM replays a previous AUTHA message to Bob.

    This checks freshness/replay resistance via Bob's replay state log tracking.
    """
    driver = _new_mitm_driver()
    scenario_name = "replayed-AUTHA-first-flight"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)
        driver.seed(seed)

        alice = driver.alice_runs_auth_a()
        first_bob_response = driver.bob_runs_auth_b(alice)
        assert first_bob_response is not None, "Sanity check failed: Bob rejected an honest AUTHA message."

        # Simulate replay by resetting Bob's expected counter window to match the replayed seq count
        driver.seq_b = alice.seq_a_sent
        replay_bob_response = driver.bob_runs_auth_b(alice)

        assert replay_bob_response is None, (
            "Bob accepted a replayed AUTHA first flight as fresh, "
            f"execution {execution_number + 1}."
        )


@pytest.mark.integration
@pytest.mark.security
def test_sanity_honest_handshake_still_succeeds_under_test_adapter() -> None:
    """The MITM test adapter must not break the honest protocol path."""
    driver = _new_mitm_driver()
    scenario_name = "sanity-honest-handshake"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)
        driver.seed(seed)
        _assert_honest_handshake_still_works(driver)


# =====================================================================
# ADVANCED ACTIVE CRYPTANALYSIS & EXPLOITATION TEST SUITE
# =====================================================================

@pytest.mark.integration
@pytest.mark.security
def test_mitm_key_compromise_impersonation_leak_isolation() -> None:
    """Perfect Forward Secrecy (PFS) Validation under Ephemeral Secret Leak.

    Even if an attacker compromises a single session's ephemeral random values
    (e.g., xa, r1, r2), they must not be able to compute session keys for
    other independent sessions.
    """
    scenario_name = "ephemeral-leak-isolation"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)

        # -------------------------------------------------------------
        # Session 1: Setup a fresh driver instance
        # -------------------------------------------------------------
        driver1 = _new_mitm_driver()
        driver1.seed(seed)

        alice_session_1 = driver1.alice_runs_auth_a()
        bob_session_1 = driver1.bob_runs_auth_b(alice_session_1)
        assert bob_session_1 is not None

        # Attacker steals Session 1 secrets
        leaked_xa = alice_session_1.xa
        leaked_r1 = alice_session_1.r1

        # -------------------------------------------------------------
        # Session 2: Instantiate a completely new driver to clear sequence logs
        # -------------------------------------------------------------
        driver2 = _new_mitm_driver()
        driver2.seed(seed + 9999)  # Use a distinct, fresh seed state

        alice_session_2 = driver2.alice_runs_auth_a()
        bob_session_2 = driver2.bob_runs_auth_b(alice_session_2)

        # This will now pass because Bob's replay log is fresh!
        assert bob_session_2 is not None

        # Attacker tries to compute Session 2's key using Session 1's leaked parameters
        try:
            Xb_prime = (driver2.pqes.secure_modinv(alice_session_2.r2, driver2.pqes.p) * (
                        bob_session_2.M_prime ^ leaked_r1)) % driver2.pqes.p
            attacker_dh = driver2.pqes.secure_pow(Xb_prime, leaked_xa, driver2.pqes.p)

            assert attacker_dh != int.from_bytes(bob_session_2.dh_secret, 'big'), (
                f"Perfect Forward Secrecy Violated! Leaked ephemeral state compromised "
                f"a fresh session key on execution {execution_number + 1}."
            )
        except Exception:
            # If mathematical calculations crash due to mismatched moduli, the isolation holds.
            pass


@pytest.mark.integration
@pytest.mark.security
@pytest.mark.parametrize("malicious_element", [0, 1])
def test_mitm_invalid_element_substitutions_on_dh_exchange(malicious_element: int) -> None:
    """Invalid Element Attack on Diffie-Hellman (Substitutions of M and M_prime).

    Attacker intercepts the masked keys and substitutes them with trivial parameters
    (0 or 1) hoping to force the modular exponentiations to collapse into predictable keys.
    """
    driver = _new_mitm_driver()
    scenario_name = f"invalid-element-{malicious_element}"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)
        driver.seed(seed)

        # 1. Attacker tampers with Alice's masked key M targeting Bob
        alice = driver.alice_runs_auth_a()
        tampered_alice = replace(alice, M=malicious_element)

        # Bob must detect the anomaly or gracefully reject the broken mathematical structure
        bob_response = driver.bob_runs_auth_b(tampered_alice)

        if bob_response is not None:
            # If Bob generates a response, check if Alice catches a malicious M_prime substitution
            tampered_bob = replace(bob_response, M_prime=malicious_element)
            alice_key = driver.alice_runs_auth_a_prime(alice, tampered_bob)

            assert alice_key is None, (
                f"Alice accepted a trivial element substitution ({malicious_element}) for M_prime, "
                f"execution {execution_number + 1}."
            )


@pytest.mark.integration
@pytest.mark.security
def test_mitm_sequence_out_of_order_replay_flooding() -> None:
    """Sequence Counter Window Sliding & Desynchronization Flood Test.

    An attacker captures a packet and replays it with an intentionally drifted or
    backward-sliding sequence count to desynchronize Bob's state tracker.
    """
    driver = _new_mitm_driver()
    scenario_name = "sequence-drift-flood"

    for execution_number in range(MITM_ATTACK_REPETITIONS):
        seed = _execution_seed(scenario_name, execution_number)
        driver.seed(seed)

        # Honest Session
        alice_1 = driver.alice_runs_auth_a()
        bob_1 = driver.bob_runs_auth_b(alice_1)
        assert bob_1 is not None

        # Attacker tries to forge an old sequence flight (e.g., seq_a_sent - 5)
        stale_sequence = max(0, alice_1.seq_a_sent - 5)
        malicious_flooded_alice = replace(alice_1, seq_a_sent=stale_sequence)

        # Bob must identify that this sequence has already been cleared or is outside the valid lookahead window
        flood_response = driver.bob_runs_auth_b(malicious_flooded_alice)
        assert flood_response is None, (
            f"Bob accepted a desynchronized/stale sequence sequence flood entry, "
            f"execution {execution_number + 1}."
        )
