package init_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	boxinit "github.com/slok/agebox/internal/box/init"
	"github.com/slok/agebox/internal/model"
	"github.com/slok/agebox/internal/storage/storagemock"
)

func TestInitBox(t *testing.T) {
	tests := map[string]struct {
		mock   func(mtr *storagemock.TrackRepository)
		expErr bool
	}{
		"A uninitialized box should be initialized correctly.": {
			mock: func(mtr *storagemock.TrackRepository) {
				mtr.On("GetSecretRegistry", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
				mtr.On("SaveSecretRegistry", mock.Anything, model.SecretRegistry{}).Once().Return(nil)
			},
		},

		"An already initialized box should fail.": {
			mock: func(mtr *storagemock.TrackRepository) {
				mtr.On("GetSecretRegistry", mock.Anything).Once().Return(nil, nil)
			},
			expErr: true,
		},

		"Having an error saving the registry should fail.": {
			mock: func(mtr *storagemock.TrackRepository) {
				mtr.On("GetSecretRegistry", mock.Anything).Once().Return(nil, fmt.Errorf("something"))
				mtr.On("SaveSecretRegistry", mock.Anything, model.SecretRegistry{}).Once().Return(fmt.Errorf("something"))
			},
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			// Mocks.
			mtr := &storagemock.TrackRepository{}
			test.mock(mtr)

			// Prepare and execute.
			svc, err := boxinit.NewService(boxinit.ServiceConfig{TrackRepo: mtr})
			require.NoError(err)

			err = svc.InitBox(context.TODO())

			// check.
			if test.expErr {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
			mtr.AssertExpectations(t)
		})
	}
}
