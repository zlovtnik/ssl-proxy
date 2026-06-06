package alerts

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/config"
)

func TestConfigFromSearchConfig(t *testing.T) {
	cfg := ConfigFromSearchConfig(testSearchConfig())

	require.Equal(t, int64(12), cfg.NearDupThreshold)
	require.Equal(t, 0.9, cfg.APRiskThreshold)
	require.Equal(t, int32(5), cfg.GraphMaxDepth)
	require.Equal(t, -20.0, cfg.SeqThreshold)
	require.Equal(t, 40.0, cfg.TravelMaxSpeedMPS)
	require.Equal(t, int32(30), cfg.DNSLookbackMinutes)
}

func TestTerminationFilterMatchesRawAndSemanticTokens(t *testing.T) {
	require.True(t, HasTerminationToken("AUTH DEAUTH", ""))
	require.True(t, HasTerminationToken("AUTH ASSOC_REQ", "DISCOVERY TERMINATION"))
	require.False(t, HasTerminationToken("PROBE_REQ AUTH ASSOC_REQ", "DISCOVERY ASSOCIATION"))
}

func TestHaversineDistanceIsCloseForOneEquatorDegree(t *testing.T) {
	meters := HaversineMeters(0, 0, 0, 1)

	require.InDelta(t, 111195.0, meters, 250.0)
}

func TestImpossibleTravelSpeedRequiresDistinctSensorOrLocation(t *testing.T) {
	t0 := time.Unix(1700000000, 0).UTC()
	t1 := time.Unix(1700000060, 0).UTC()
	sameSensor := TravelObservation{ClusterID: 1, SensorID: "sensor-a", ObservedAt: t0, Latitude: 0, Longitude: 0}
	sameSensorLater := TravelObservation{ClusterID: 1, SensorID: "sensor-a", ObservedAt: t1, Latitude: 0, Longitude: 1}
	require.Nil(t, ImpossibleTravelSpeedMPS(sameSensor, sameSensorLater))

	otherSensor := TravelObservation{ClusterID: 1, SensorID: "sensor-b", ObservedAt: t1, Latitude: 0, Longitude: 1}
	speed := ImpossibleTravelSpeedMPS(sameSensor, otherSensor)
	require.NotNil(t, speed)
	require.Greater(t, *speed, 1800.0)
}

func testSearchConfig() config.Config {
	return config.Config{
		AlertNearDupThreshold:   12,
		AlertAPRiskThreshold:    0.9,
		AlertGraphMaxDepth:      5,
		AlertSeqThreshold:       -20.0,
		AlertTravelMaxSpeedMPS:  40.0,
		AlertDNSLookbackMinutes: 30,
	}
}
