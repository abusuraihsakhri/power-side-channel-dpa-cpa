"""
Countermeasure Testing Module for CPA/DPA Side-Channel Attack Agent.
Tests resistance to masking, hiding, shuffling, and threshold implementation countermeasures.
Standard: ISO/IEC 17825 Side-Channel Testing
"""
import math
import random
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from enum import Enum


class CountermeasureType(str, Enum):
    MASKING_FIRST_ORDER = "first_order_masking"
    MASKING_SECOND_ORDER = "second_order_masking"
    HIDING_CLOCK_JITTER = "clock_jitter"
    HIDING_NOISE_INJECTION = "noise_injection"
    SHUFFLING_SBOX = "sbox_shuffling"
    SHUFFLING_ROUND = "round_shuffling"
    THRESHOLD_IMPLEMENTATION = "threshold_implementation"


class ResistanceLevel(str, Enum):
    VULNERABLE = "VULNERABLE"
    PARTIALLY_RESISTANT = "PARTIALLY_RESISTANT"
    RESISTANT = "RESISTANT"


@dataclass
class CountermeasureTestResult:
    """Result of testing a specific countermeasure against CPA/DPA."""
    countermeasure: CountermeasureType
    resistance_level: ResistanceLevel
    traces_for_key_recovery: int
    confidence_score: float
    masking_order_detected: int
    details: str = ""
    recommendations: List[str] = field(default_factory=list)


@dataclass
class MaskingTestResult:
    """Detailed result for masking countermeasure testing."""
    countermeasure: CountermeasureType
    is_first_order_secure: bool
    is_second_order_secure: bool
    first_order_correlation: float
    second_order_correlation: float
    noise_amplitude: float
    snr_db: float
    resistance_level: ResistanceLevel = ResistanceLevel.VULNERABLE


@dataclass
class HidingTestResult:
    """Detailed result for hiding countermeasure testing."""
    countermeasure: CountermeasureType
    timing_variance_ns: float
    noise_floor_db: float
    snr_db: float
    traces_needed_for_attack: int
    resistance_level: ResistanceLevel = ResistanceLevel.VULNERABLE


class CountermeasureTestEngine:
    """
    Engine for testing side-channel countermeasure effectiveness against CPA/DPA attacks.
    Implements masking, hiding, shuffling, and threshold implementation evaluation.
    """

    STANDARD = "ISO/IEC 17825 Side-Channel Testing"

    @staticmethod
    def generate_masked_traces(
        n_traces: int = 10000,
        n_samples: int = 100,
        masking_order: int = 1,
        noise_std: float = 0.0,
    ) -> Tuple[List[List[float]], List[bytes]]:
        """
        Generate simulated power traces with masking countermeasure applied.
        Returns (traces, plaintexts) where traces include masking noise.
        """
        random.seed(42)
        traces = []
        plaintexts = []
        secret_key = bytes([0x2B] * 16)

        for _ in range(n_traces):
            pt = bytes([random.randint(0, 255) for _ in range(16)])
            plaintexts.append(pt)

            # Simulate masked power trace
            trace = []
            for s in range(n_samples):
                # Base signal from Hamming weight of S-Box output
                sbox_out = pt[s % 16] ^ secret_key[s % 16]
                base_signal = bin(sbox_out).count("1") / 8.0

                # Apply masking: add random mask shares
                mask_shares = [random.random() for _ in range(masking_order)]
                masked_signal = base_signal
                for share in mask_shares:
                    masked_signal += (random.random() - 0.5) * (1.0 / masking_order)

                # Add measurement noise
                noise = random.gauss(0, noise_std) if noise_std > 0 else 0.0
                trace.append(masked_signal + noise)

            traces.append(trace)

        return traces, plaintexts

    @staticmethod
    def compute_correlation(
        traces: List[List[float]],
        values: List[float],
        sample_idx: int,
    ) -> float:
        """Compute Pearson correlation between trace samples and intermediate values."""
        n = len(traces)
        if n < 2:
            return 0.0

        trace_vals = [traces[i][sample_idx] for i in range(n)]
        mean_t = sum(trace_vals) / n
        mean_v = sum(values) / n

        cov = sum((trace_vals[i] - mean_t) * (values[i] - mean_v) for i in range(n))
        std_t = math.sqrt(sum((t - mean_t) ** 2 for t in trace_vals))
        std_v = math.sqrt(sum((v - mean_v) ** 2 for v in values))

        if std_t == 0 or std_v == 0:
            return 0.0
        return cov / (std_t * std_v)

    def test_masking_countermeasure(
        self,
        masking_order: int = 1,
        n_traces: int = 10000,
    ) -> MaskingTestResult:
        """
        Test first-order and higher-order masking countermeasures against CPA.
        A masked implementation should resist first-order CPA attacks.
        """
        traces, plaintexts = self.generate_masked_traces(
            n_traces=n_traces,
            masking_order=masking_order,
            noise_std=0.1,
        )

        # Compute first-order correlation
        secret_key_byte = 0x2B
        values = []
        for pt in plaintexts:
            sbox_out = pt[0] ^ secret_key_byte
            values.append(bin(sbox_out).count("1") / 8.0)

        first_order_corr = abs(self.compute_correlation(traces, values, 0))

        # Compute second-order correlation (for higher-order attacks)
        second_order_corr = 0.0
        if masking_order >= 1:
            # Second-order: combine two sample points
            combined = [
                traces[i][0] * traces[i][1] for i in range(len(traces))
            ]
            mean_c = sum(combined) / len(combined)
            mean_v = sum(values) / len(values)
            cov = sum((combined[i] - mean_c) * (values[i] - mean_v) for i in range(len(combined)))
            std_c = math.sqrt(sum((c - mean_c) ** 2 for c in combined))
            std_v = math.sqrt(sum((v - mean_v) ** 2 for v in values))
            if std_c > 0 and std_v > 0:
                second_order_corr = abs(cov / (std_c * std_v))

        # Determine resistance level
        first_order_secure = first_order_corr < 0.05
        second_order_secure = second_order_corr < 0.05 if masking_order >= 1 else True

        if first_order_secure and second_order_secure:
            resistance = ResistanceLevel.RESISTANT
        elif first_order_secure:
            resistance = ResistanceLevel.PARTIALLY_RESISTANT
        else:
            resistance = ResistanceLevel.VULNERABLE

        # Compute SNR
        signal_power = sum(v ** 2 for v in values) / len(values)
        noise_power = sum(
            (traces[i][0] - values[i]) ** 2 for i in range(len(traces))
        ) / len(traces)
        snr_db = 10 * math.log10(signal_power / max(noise_power, 1e-10))

        return MaskingTestResult(
            countermeasure=CountermeasureType.MASKING_FIRST_ORDER if masking_order == 1
            else CountermeasureType.MASKING_SECOND_ORDER,
            is_first_order_secure=first_order_secure,
            is_second_order_secure=second_order_secure,
            first_order_correlation=round(first_order_corr, 6),
            second_order_correlation=round(second_order_corr, 6),
            noise_amplitude=0.1,
            snr_db=round(snr_db, 2),
            resistance_level=resistance,
        )

    def test_hiding_countermeasure(
        self,
        jitter_cycles: int = 10,
        noise_std: float = 2.0,
        n_traces: int = 10000,
    ) -> HidingTestResult:
        """
        Test hiding countermeasures (clock jitter, noise injection) against DPA.
        Hiding increases the number of traces needed for successful attack.
        """
        traces, plaintexts = self.generate_masked_traces(
            n_traces=n_traces,
            masking_order=0,
            noise_std=noise_std,
        )

        secret_key_byte = 0x2B
        values = []
        for pt in plaintexts:
            sbox_out = pt[0] ^ secret_key_byte
            values.append(bin(sbox_out).count("1") / 8.0)

        corr = abs(self.compute_correlation(traces, values, 0))

        # Estimate traces needed: inversely proportional to correlation squared
        if corr > 0:
            traces_needed = int(8.0 / (corr ** 2))
        else:
            traces_needed = 10**9  # Effectively infinite

        snr_db = -10 * math.log10(noise_std) if noise_std > 0 else 60.0

        if traces_needed > 100000:
            resistance = ResistanceLevel.RESISTANT
        elif traces_needed > 10000:
            resistance = ResistanceLevel.PARTIALLY_RESISTANT
        else:
            resistance = ResistanceLevel.VULNERABLE

        return HidingTestResult(
            countermeasure=CountermeasureType.HIDING_NOISE_INJECTION,
            timing_variance_ns=jitter_cycles * 0.5,
            noise_floor_db=-60.0,
            snr_db=round(snr_db, 2),
            traces_needed_for_attack=traces_needed,
            resistance_level=resistance,
        )

    def test_shuffling_countermeasure(
        self,
        n_traces: int = 10000,
        n_shuffled_ops: int = 16,
    ) -> CountermeasureTestResult:
        """
        Test shuffling countermeasures against CPA.
        Shuffling randomizes operation order, requiring more traces.
        """
        random.seed(42)
        secret_key_byte = 0x2B
        correct_rank = 0
        total_attempts = 0

        for _ in range(min(n_traces, 1000)):
            pt = random.randint(0, 255)
            sbox_out = pt ^ secret_key_byte
            hw = bin(sbox_out).count("1")

            # With shuffling, the signal is spread across multiple operations
            shuffled_idx = random.randint(0, n_shuffled_ops - 1)
            # The signal at any single operation is attenuated by 1/sqrt(n_ops)
            attenuated_signal = hw / math.sqrt(n_shuffled_ops)
            noise = random.gauss(0, 1.0)

            total_attempts += 1
            if abs(attenuated_signal + noise - hw / n_shuffled_ops) < 0.5:
                correct_rank += 1

        confidence = correct_rank / max(total_attempts, 1)
        traces_for_recovery = int(n_traces / max(confidence, 0.01))

        if traces_for_recovery > 100000:
            resistance = ResistanceLevel.RESISTANT
        elif traces_for_recovery > 10000:
            resistance = ResistanceLevel.PARTIALLY_RESISTANT
        else:
            resistance = ResistanceLevel.VULNERABLE

        return CountermeasureTestResult(
            countermeasure=CountermeasureType.SHUFFLING_SBOX,
            resistance_level=resistance,
            traces_for_key_recovery=traces_for_recovery,
            confidence_score=round(confidence, 4),
            masking_order_detected=0,
            details=f"S-Box shuffling with {n_shuffled_ops} operations tested.",
            recommendations=[
                "Combine shuffling with masking for stronger protection",
                "Increase shuffle count to >32 for production use",
            ],
        )

    def full_countermeasure_suite(self) -> Dict[str, Any]:
        """Run the complete countermeasure testing suite."""
        masking_1st = self.test_masking_countermeasure(masking_order=1)
        hiding = self.test_hiding_countermeasure()
        shuffling = self.test_shuffling_countermeasure()

        return {
            "standard": self.STANDARD,
            "masking_first_order": {
                "resistance": masking_1st.resistance_level.value,
                "first_order_correlation": masking_1st.first_order_correlation,
                "snr_db": masking_1st.snr_db,
            },
            "hiding_noise_injection": {
                "resistance": hiding.resistance_level.value,
                "traces_needed": hiding.traces_needed_for_attack,
                "snr_db": hiding.snr_db,
            },
            "shuffling_sbox": {
                "resistance": shuffling.resistance_level.value,
                "traces_for_recovery": shuffling.traces_for_key_recovery,
                "confidence": shuffling.confidence_score,
            },
        }
