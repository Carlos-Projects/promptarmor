from dataclasses import dataclass

import numpy as np
from mcp_taxonomy import AttackCategory, Confidence, Severity


@dataclass
class WhitelistResult:
    accepted: bool
    score: float = 0.0
    distance: float = 0.0
    severity: Severity = Severity.INFO
    confidence: Confidence = Confidence.NONE
    category: AttackCategory = AttackCategory.POLICY_VIOLATION


class LatentWhitelist:
    def __init__(
        self,
        threshold: float = 0.7,
        ellipsoid_scale: float = 1.0,
        known_benign: list[list[float]] | None = None,
    ):
        self.threshold = threshold
        self.ellipsoid_scale = ellipsoid_scale
        self._mean: np.ndarray | None = None
        self._cov: np.ndarray | None = None
        self._cov_inv: np.ndarray | None = None
        self._n_samples: int = 0

        if known_benign:
            self.fit(known_benign)

    def fit(self, embeddings: list[list[float]]) -> None:
        if not embeddings:
            return
        data = np.array(embeddings, dtype=np.float64)
        if data.ndim != 2:
            return
        self._mean = np.mean(data, axis=0)
        self._cov = np.cov(data, rowvar=False)
        self._n_samples = data.shape[0]

        if self._cov.ndim == 0 or self._cov.size == 1:
            self._cov = np.array([[float(self._cov)]])
        try:
            self._cov_inv = np.linalg.inv(self._cov + np.eye(self._cov.shape[0]) * 1e-6)
        except np.linalg.LinAlgError:
            self._cov_inv = np.linalg.pinv(self._cov + np.eye(self._cov.shape[0]) * 1e-6)

    def mahalanobis_distance(self, embedding: list[float]) -> float:
        if self._mean is None or self._cov_inv is None:
            return 0.0
        x = np.array(embedding, dtype=np.float64)
        diff = x - self._mean
        try:
            dist = float(np.sqrt(diff @ self._cov_inv @ diff))
        except (ValueError, np.linalg.LinAlgError):
            dist = float(np.linalg.norm(diff))
        return dist

    def score(self, embedding: list[float]) -> float:
        dist = self.mahalanobis_distance(embedding)
        acceptance = float(np.exp(-dist / (self.ellipsoid_scale + 1e-8)))
        return min(max(acceptance, 0.0), 1.0)

    def check(self, embedding: list[float]) -> WhitelistResult:
        dist = self.mahalanobis_distance(embedding)
        score = self.score(embedding)
        accepted = score >= self.threshold

        if not accepted:
            if score < 0.3:
                severity = Severity.CRITICAL
                confidence = Confidence.HIGH
            elif score < 0.5:
                severity = Severity.HIGH
                confidence = Confidence.MEDIUM
            else:
                severity = Severity.MEDIUM
                confidence = Confidence.LOW
        else:
            severity = Severity.INFO
            confidence = Confidence.NONE

        return WhitelistResult(
            accepted=accepted,
            score=score,
            distance=dist,
            severity=severity,
            confidence=confidence,
            category=AttackCategory.ANOMALY if not accepted else AttackCategory.POLICY_VIOLATION,
        )
