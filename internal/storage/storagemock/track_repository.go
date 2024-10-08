// Code generated by mockery v2.46.2. DO NOT EDIT.

package storagemock

import (
	context "context"

	model "github.com/slok/agebox/internal/model"
	mock "github.com/stretchr/testify/mock"
)

// TrackRepository is an autogenerated mock type for the TrackRepository type
type TrackRepository struct {
	mock.Mock
}

// GetSecretRegistry provides a mock function with given fields: ctx
func (_m *TrackRepository) GetSecretRegistry(ctx context.Context) (*model.SecretRegistry, error) {
	ret := _m.Called(ctx)

	if len(ret) == 0 {
		panic("no return value specified for GetSecretRegistry")
	}

	var r0 *model.SecretRegistry
	var r1 error
	if rf, ok := ret.Get(0).(func(context.Context) (*model.SecretRegistry, error)); ok {
		return rf(ctx)
	}
	if rf, ok := ret.Get(0).(func(context.Context) *model.SecretRegistry); ok {
		r0 = rf(ctx)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.SecretRegistry)
		}
	}

	if rf, ok := ret.Get(1).(func(context.Context) error); ok {
		r1 = rf(ctx)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// SaveSecretRegistry provides a mock function with given fields: ctx, reg
func (_m *TrackRepository) SaveSecretRegistry(ctx context.Context, reg model.SecretRegistry) error {
	ret := _m.Called(ctx, reg)

	if len(ret) == 0 {
		panic("no return value specified for SaveSecretRegistry")
	}

	var r0 error
	if rf, ok := ret.Get(0).(func(context.Context, model.SecretRegistry) error); ok {
		r0 = rf(ctx, reg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// NewTrackRepository creates a new instance of TrackRepository. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
// The first argument is typically a *testing.T value.
func NewTrackRepository(t interface {
	mock.TestingT
	Cleanup(func())
}) *TrackRepository {
	mock := &TrackRepository{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
