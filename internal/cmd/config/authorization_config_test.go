// Copyright IBM Corp. 2020, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse_AuthorizationBlock(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		hcl       string
		wantErr   bool
		wantComp  string
		wantRecon time.Duration
		wantLag   time.Duration
	}{
		{
			name: "absent block leaves nil and defaults are applied by normalize",
			hcl:  `controller {}`,
		},
		{
			name: "explicit union and durations",
			hcl: `controller {
				authorization {
					scope_composition = "union"
					revocation_reconcile_interval = "10s"
					max_revocation_signal_lag = "45s"
				}
			}`,
			wantComp:  "union",
			wantRecon: 10 * time.Second,
			wantLag:   45 * time.Second,
		},
		{
			name: "intersection accepted",
			hcl: `controller {
				authorization { scope_composition = "intersection" }
			}`,
			wantComp:  "intersection",
			wantRecon: DefaultRevocationReconcileInterval,
			wantLag:   DefaultMaxRevocationSignalLag,
		},
		{
			name: "empty composition defaults to union",
			hcl: `controller {
				authorization { revocation_reconcile_interval = "5s" }
			}`,
			wantComp:  DefaultScopeComposition,
			wantRecon: 5 * time.Second,
			wantLag:   DefaultMaxRevocationSignalLag,
		},
		{
			name: "unknown composition fails closed",
			hcl: `controller {
				authorization { scope_composition = "inherit" }
			}`,
			wantErr: true,
		},
		{
			name: "negative interval rejected",
			hcl: `controller {
				authorization { revocation_reconcile_interval = "-1s" }
			}`,
			wantErr: true,
		},
		{
			name: "interval exceeding lag rejected so the fail-closed window holds",
			hcl: `controller {
				authorization {
					revocation_reconcile_interval = "90s"
					max_revocation_signal_lag = "30s"
				}
			}`,
			wantErr: true,
		},
		{
			name: "malformed duration rejected",
			hcl: `controller {
				authorization { max_revocation_signal_lag = "not-a-duration" }
			}`,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := Parse(tc.hcl)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, cfg.Controller)

			if tc.wantComp == "" {
				// Absent block: nothing to normalize.
				assert.Nil(t, cfg.Controller.Authorization)
				return
			}
			require.NotNil(t, cfg.Controller.Authorization)
			a := cfg.Controller.Authorization
			assert.Equal(t, tc.wantComp, a.ScopeComposition)
			assert.Equal(t, tc.wantRecon, a.RevocationReconcileIntervalDuration)
			assert.Equal(t, tc.wantLag, a.MaxRevocationSignalLagDuration)
		})
	}
}

func TestNormalizeAuthorization_NilSafe(t *testing.T) {
	t.Parallel()
	assert.NoError(t, normalizeAuthorization(nil))
}

// TestNormalizeAuthorization_Defaults pins the documented default tuning so a
// silent constant change fails a test.
func TestNormalizeAuthorization_Defaults(t *testing.T) {
	t.Parallel()
	a := &Authorization{}
	require.NoError(t, normalizeAuthorization(a))
	assert.Equal(t, "union", a.ScopeComposition)
	assert.Equal(t, 30*time.Second, a.RevocationReconcileIntervalDuration)
	assert.Equal(t, 60*time.Second, a.MaxRevocationSignalLagDuration)
}
