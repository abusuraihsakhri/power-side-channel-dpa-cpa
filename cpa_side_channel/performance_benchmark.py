"""
Performance Benchmarking Module for CPA/DPA Side-Channel Attack Agent.
Benchmarks CPA convergence, correlation speed, and key ranking latency.
Standard: ISO/IEC 17825 Side-Channel Testing
"""
import math
import time
import random
import statistics
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple


@dataclass
class CPAConvergenceResult:
    """Result of CPA convergence benchmark."""
    n_traces: int
    key_rank: int
    correct_key_recovered: bool
    elapsed_ms: float
    correlation_peak: float


@dataclass
class CorrelationBenchmarkResult:
    """Result of correlation computation benchmark."""
    n_traces: int
    n_samples: int
    elapsed_ms: float
    throughput_traces_per_sec: float


@dataclass
class KeyRankingBenchmarkResult:
    """Result of key candidate ranking benchmark."""
    n_candidates: int
    elapsed_ms: float
    top_candidate_correct: bool
    ranking_confidence: float


@dataclass
class BenchmarkSuiteResult:
    """Aggregated benchmark results."""
    convergence_results: List[CPAConvergenceResult] = field(default_factory=list)
    correlation_results: List[CorrelationBenchmarkResult] = field(default_factory=list)
    ranking_results: List[KeyRankingBenchmarkResult] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)


# AES S-Box
AES_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]


class PerformanceBenchmarkEngine:
    """
    Performance benchmarking engine for CPA/DPA side-channel analysis.
    Measures convergence speed, correlation throughput, and key ranking latency.
    """

    SECRET_KEY = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                        0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])

    def generate_traces(self, n_traces: int, n_samples: int = 50) -> Tuple[List[List[float]], List[bytes]]:
        """Generate simulated power traces for benchmarking."""
        random.seed(42)
        traces = []
        plaintexts = []
        for _ in range(n_traces):
            pt = bytes([random.randint(0, 255) for _ in range(16)])
            plaintexts.append(pt)
            trace = []
            for s in range(n_samples):
                byte_idx = s % 16
                sbox_out = AES_SBOX[pt[byte_idx] ^ self.SECRET_KEY[byte_idx]]
                hw = bin(sbox_out).count("1") / 8.0
                noise = random.gauss(0, 0.1)
                trace.append(hw + noise)
            traces.append(trace)
        return traces, plaintexts

    def _pearson_correlation(self, x: List[float], y: List[float]) -> float:
        """Compute Pearson correlation coefficient."""
        n = len(x)
        if n < 2:
            return 0.0
        mean_x = sum(x) / n
        mean_y = sum(y) / n
        cov = sum((x[i] - mean_x) * (y[i] - mean_y) for i in range(n))
        std_x = math.sqrt(sum((xi - mean_x) ** 2 for xi in x))
        std_y = math.sqrt(sum((yi - mean_y) ** 2 for yi in y))
        if std_x == 0 or std_y == 0:
            return 0.0
        return cov / (std_x * std_y)

    def benchmark_cpa_convergence(
        self,
        trace_counts: Optional[List[int]] = None,
    ) -> List[CPAConvergenceResult]:
        """
        Benchmark CPA convergence: measure traces needed to recover AES key.
        Tests at multiple trace counts to find the minimum for successful recovery.
        """
        if trace_counts is None:
            trace_counts = [100, 500, 1000, 2000, 5000, 10000]

        max_traces = max(trace_counts)
        traces, plaintexts = self.generate_traces(max_traces)

        results = []
        for n in trace_counts:
            start = time.perf_counter_ns()

            # CPA attack on first byte
            best_corr = 0.0
            best_key = 0
            for key_guess in range(256):
                values = []
                for i in range(n):
                    sbox_out = AES_SBOX[plaintexts[i][0] ^ key_guess]
                    values.append(bin(sbox_out).count("1") / 8.0)
                corr = abs(self._pearson_correlation(
                    [traces[i][0] for i in range(n)], values
                ))
                if corr > best_corr:
                    best_corr = corr
                    best_key = key_guess

            elapsed_ms = (time.perf_counter_ns() - start) / 1e6
            correct = best_key == self.SECRET_KEY[0]

            # Compute key rank
            all_corrs = []
            for key_guess in range(256):
                values = []
                for i in range(n):
                    sbox_out = AES_SBOX[plaintexts[i][0] ^ key_guess]
                    values.append(bin(sbox_out).count("1") / 8.0)
                corr = abs(self._pearson_correlation(
                    [traces[i][0] for i in range(n)], values
                ))
                all_corrs.append(corr)

            all_corrs.sort(reverse=True)
            key_rank = all_corrs.index(best_corr) + 1 if best_corr in all_corrs else 256

            results.append(CPAConvergenceResult(
                n_traces=n,
                key_rank=key_rank,
                correct_key_recovered=correct,
                elapsed_ms=round(elapsed_ms, 2),
                correlation_peak=round(best_corr, 6),
            ))

        return results

    def benchmark_correlation_speed(
        self,
        trace_counts: Optional[List[int]] = None,
    ) -> List[CorrelationBenchmarkResult]:
        """
        Benchmark Pearson correlation computation speed for varying trace counts.
        """
        if trace_counts is None:
            trace_counts = [1000, 5000, 10000, 50000]

        results = []
        for n in trace_counts:
            traces, plaintexts = self.generate_traces(min(n, 10000))
            values = [bin(AES_SBOX[plaintexts[i][0] ^ self.SECRET_KEY[0]]).count("1") / 8.0
                      for i in range(min(n, len(traces)))]

            actual_n = min(n, len(traces))
            start = time.perf_counter_ns()
            for _ in range(10):
                self._pearson_correlation(
                    [traces[i][0] for i in range(actual_n)], values
                )
            elapsed_ms = (time.perf_counter_ns() - start) / 1e6 / 10

            results.append(CorrelationBenchmarkResult(
                n_traces=actual_n,
                n_samples=1,
                elapsed_ms=round(elapsed_ms, 2),
                throughput_traces_per_sec=round(actual_n / (elapsed_ms / 1000), 0),
            ))

        return results

    def benchmark_key_ranking(
        self,
        n_candidates: int = 256,
    ) -> KeyRankingBenchmarkResult:
        """
        Benchmark key candidate ranking latency for the full AES key space.
        """
        traces, plaintexts = self.generate_traces(5000)
        n = len(traces)

        start = time.perf_counter_ns()
        correlations = []
        for key_guess in range(n_candidates):
            values = []
            for i in range(n):
                sbox_out = AES_SBOX[plaintexts[i][0] ^ key_guess]
                values.append(bin(sbox_out).count("1") / 8.0)
            corr = abs(self._pearson_correlation(
                [traces[i][0] for i in range(n)], values
            ))
            correlations.append((key_guess, corr))

        correlations.sort(key=lambda x: x[1], reverse=True)
        elapsed_ms = (time.perf_counter_ns() - start) / 1e6

        top_correct = correlations[0][0] == self.SECRET_KEY[0]
        confidence = correlations[0][1] / max(correlations[1][1], 1e-10) if len(correlations) > 1 else 1.0

        return KeyRankingBenchmarkResult(
            n_candidates=n_candidates,
            elapsed_ms=round(elapsed_ms, 2),
            top_candidate_correct=top_correct,
            ranking_confidence=round(confidence, 4),
        )

    def full_benchmark_suite(self) -> Dict[str, Any]:
        """Run the complete performance benchmark suite."""
        convergence = self.benchmark_cpa_convergence()
        correlation = self.benchmark_correlation_speed()
        ranking = self.benchmark_key_ranking()

        return {
            "convergence_benchmark": [
                {
                    "n_traces": r.n_traces,
                    "key_rank": r.key_rank,
                    "correct": r.correct_key_recovered,
                    "elapsed_ms": r.elapsed_ms,
                    "peak_correlation": r.correlation_peak,
                }
                for r in convergence
            ],
            "correlation_speed_benchmark": [
                {
                    "n_traces": r.n_traces,
                    "elapsed_ms": r.elapsed_ms,
                    "throughput_traces_per_sec": r.throughput_traces_per_sec,
                }
                for r in correlation
            ],
            "key_ranking_benchmark": {
                "n_candidates": ranking.n_candidates,
                "elapsed_ms": ranking.elapsed_ms,
                "top_correct": ranking.top_candidate_correct,
                "confidence": ranking.ranking_confidence,
            },
        }
