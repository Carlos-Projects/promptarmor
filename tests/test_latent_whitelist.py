from mcp_taxonomy import Severity

from promptarmor.filters.latent_whitelist import LatentWhitelist, WhitelistResult


class TestLatentWhitelist:
    def test_empty_fit(self):
        wl = LatentWhitelist()
        dist = wl.mahalanobis_distance([1.0, 2.0, 3.0])
        assert dist == 0.0

    def test_fit_and_score(self):
        benign = [
            [0.1, 0.2, 0.3],
            [0.2, 0.1, 0.4],
            [0.15, 0.25, 0.35],
        ]
        wl = LatentWhitelist(known_benign=benign, threshold=0.5)
        result = wl.check([0.12, 0.22, 0.32])
        assert result.accepted

    def test_anomaly_detection(self):
        benign = [
            [0.1, 0.2, 0.3],
            [0.2, 0.1, 0.4],
            [0.15, 0.25, 0.35],
        ]
        wl = LatentWhitelist(known_benign=benign, threshold=0.5)
        result = wl.check([100.0, 200.0, 300.0])
        assert not result.accepted

    def test_score_range(self):
        benign = [[1.0, 2.0], [1.5, 2.5], [2.0, 1.5]]
        wl = LatentWhitelist(known_benign=benign, threshold=0.0)
        score = wl.score([1.2, 2.1])
        assert 0.0 <= score <= 1.0

    def test_mahalanobis_distance_positive(self):
        benign = [[1.0, 2.0, 3.0], [4.0, 5.0, 6.0], [7.0, 8.0, 9.0]]
        wl = LatentWhitelist(known_benign=benign)
        dist = wl.mahalanobis_distance([1.0, 2.0, 3.0])
        assert dist >= 0.0

    def test_whitelist_result_dataclass(self):
        benign = [[0.0, 0.0], [0.1, 0.1]]
        wl = LatentWhitelist(known_benign=benign)
        result = wl.check([0.05, 0.05])
        assert isinstance(result, WhitelistResult)
        assert isinstance(result.accepted, bool)
        assert isinstance(result.score, float)
        assert isinstance(result.distance, float)

    def test_severity_for_outlier(self):
        benign = [[0.0, 0.0], [0.1, 0.1]]
        wl = LatentWhitelist(known_benign=benign, threshold=0.5)
        result = wl.check([100.0, 100.0])
        assert not result.accepted
        assert isinstance(result.severity, Severity)

    def test_ellipsoid_scale_effect(self):
        benign = [[0.0, 0.0], [1.0, 1.0]]
        wl_strict = LatentWhitelist(known_benign=benign, threshold=0.5, ellipsoid_scale=0.1)
        wl_loose = LatentWhitelist(known_benign=benign, threshold=0.5, ellipsoid_scale=10.0)
        result_strict = wl_strict.check([5.0, 5.0])
        result_loose = wl_loose.check([5.0, 5.0])
        assert result_strict.score < result_loose.score or abs(result_strict.score - result_loose.score) < 1e-6

    def test_fit_single_sample(self):
        wl = LatentWhitelist(known_benign=[[1.0, 2.0]])
        assert wl._mean is not None
        result = wl.check([1.1, 2.1])
        assert isinstance(result, WhitelistResult)

    def test_fit_without_data(self):
        wl = LatentWhitelist()
        assert wl._mean is None
        result = wl.check([1.0, 2.0])
        assert result.accepted
