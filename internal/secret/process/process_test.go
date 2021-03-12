package process_test

import (
	"context"
	"fmt"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/secret/process/processmock"
)

func TestIDProcessorChain(t *testing.T) {
	tests := map[string]struct {
		processors func() []*processmock.IDProcessor
		secret     string
		expSecret  string
		expErr     bool
	}{
		"Without processors the chain should return the same.": {
			processors: func() []*processmock.IDProcessor {
				return []*processmock.IDProcessor{}
			},
			secret:    "test",
			expSecret: "test",
		},

		"All processors should be called with the secret and pass the secret one each other.": {
			processors: func() []*processmock.IDProcessor {
				m1 := &processmock.IDProcessor{}
				m1.On("ProcessID", mock.Anything, "test").Once().Return("test1", nil)
				m2 := &processmock.IDProcessor{}
				m2.On("ProcessID", mock.Anything, "test1").Once().Return("test2", nil)
				m3 := &processmock.IDProcessor{}
				m3.On("ProcessID", mock.Anything, "test2").Once().Return("test3", nil)
				return []*processmock.IDProcessor{m1, m2, m3}
			},
			secret:    "test",
			expSecret: "test3",
		},

		"If any of the chain processor errors it should stop the chain.": {
			processors: func() []*processmock.IDProcessor {
				m1 := &processmock.IDProcessor{}
				m1.On("ProcessID", mock.Anything, "test").Once().Return("test1", nil)
				m2 := &processmock.IDProcessor{}
				m2.On("ProcessID", mock.Anything, mock.Anything).Once().Return("", fmt.Errorf("something"))
				m3 := &processmock.IDProcessor{}
				return []*processmock.IDProcessor{m1, m2, m3}
			},
			secret: "test",
			expErr: true,
		},

		"If a processor returns empty it should stop the chain and return empty as if the secret would be ignored.": {
			processors: func() []*processmock.IDProcessor {
				m1 := &processmock.IDProcessor{}
				m1.On("ProcessID", mock.Anything, "test").Once().Return("test1", nil)
				m2 := &processmock.IDProcessor{}
				m2.On("ProcessID", mock.Anything, "test1").Once().Return("", nil)
				m3 := &processmock.IDProcessor{}
				return []*processmock.IDProcessor{m1, m2, m3}
			},
			secret:    "test",
			expSecret: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks.
			mProcessors := test.processors()
			processors := make([]process.IDProcessor, 0, len(mProcessors))
			for _, mp := range mProcessors {
				processors = append(processors, mp)
			}

			p := process.NewIDProcessorChain(processors...)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}

			for _, mp := range mProcessors {
				mp.AssertExpectations(t)
			}
		})
	}
}

func TestIgnoreAlreadyProcessed(t *testing.T) {
	tests := map[string]struct {
		cache     map[string]struct{}
		secret    string
		expSecret string
		expErr    bool
	}{
		"Empty cache and empty secret should return the same empty secret.": {
			cache:     map[string]struct{}{},
			secret:    "",
			expSecret: "",
		},

		"Cache should be automatically initialialized.": {
			cache:     nil,
			secret:    "test",
			expSecret: "test",
		},

		"A regular secret not in cache should be a valid processable secret.": {
			cache:     map[string]struct{}{},
			secret:    "test",
			expSecret: "test",
		},

		"A regular secret in cache should be ignored.": {
			cache: map[string]struct{}{
				"test": {},
			},
			secret:    "test",
			expSecret: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			p := process.NewIgnoreAlreadyProcessed(test.cache)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}
		})
	}
}

func TestTrackedState(t *testing.T) {
	tests := map[string]struct {
		ignoreMissing  bool
		trackedSecrets map[string]struct{}
		secret         string
		expSecret      string
		expErr         bool
	}{
		"Having a tracked secret should allow.": {
			trackedSecrets: map[string]struct{}{
				"test0": {},
				"test1": {},
			},
			secret:    "test1",
			expSecret: "test1",
		},

		"Not having a tracked secret should fail.": {
			trackedSecrets: map[string]struct{}{},
			secret:         "test1",
			expErr:         true,
		},

		"Not having a tracked secret and ignoring, should not fail.": {
			ignoreMissing:  true,
			trackedSecrets: map[string]struct{}{},
			secret:         "test1",
			expSecret:      "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			p := process.NewTrackedState(test.trackedSecrets, test.ignoreMissing, log.Noop)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}
		})
	}
}

func TestIncludeRegexMatch(t *testing.T) {
	tests := map[string]struct {
		regex     *regexp.Regexp
		secret    string
		expSecret string
		expErr    bool
	}{
		"A nil regex should match everything.": {
			secret:    "test1",
			expSecret: "test1",
		},

		"A matching secret should be allowed (all).": {
			regex:     regexp.MustCompile(".*"),
			secret:    "test1",
			expSecret: "test1",
		},

		"A matching secret should be allowed.": {
			regex:     regexp.MustCompile("^test[0-9]$"),
			secret:    "test2",
			expSecret: "test2",
		},

		"A not matching secret should be ignored.": {
			regex:     regexp.MustCompile("^notest[0-9]$"),
			secret:    "test1",
			expSecret: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			p := process.NewIncludeRegexMatch(test.regex, log.Noop)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}
		})
	}
}
