package process_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/slok/agebox/internal/log"
	"github.com/slok/agebox/internal/secret/process"
	"github.com/slok/agebox/internal/storage/storagemock"
)

func TestPathSanitizer(t *testing.T) {
	tests := map[string]struct {
		extension string
		secret    string
		expSecret string
		expErr    bool
	}{
		"Having a secret without extension it should return the path as it is.": {
			secret:    "test",
			expSecret: "test",
		},

		"Having a secret with extension it should return the path sanitized (default extension).": {
			secret:    "test.agebox",
			expSecret: "test",
		},

		"Having a secret with extension it should return the path sanitized (custom extension).": {
			extension: ".something",
			secret:    "test.something",
			expSecret: "test",
		},

		"Having a secret with extension it should return the path sanitized (custom extension without dot).": {
			extension: "something",
			secret:    "test.something",
			expSecret: "test",
		},

		"Having a secret with relative prefix.": {
			secret:    "./test.something",
			expSecret: "test.something",
		},

		"Having a secret with directory suffix.": {
			secret:    "something/test.something/",
			expSecret: "something/test.something",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			p := process.NewPathSanitizer(test.extension)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}
		})
	}
}

func TestDecryptionPathState(t *testing.T) {
	tests := map[string]struct {
		forceDecrypt bool
		mock         func(m *storagemock.SecretRepository)
		secret       string
		expSecret    string
		expErr       bool
	}{
		"If checking an encrypted secret exists has an error we should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, fmt.Errorf("something"))
			},
			secret: "test",
			expErr: true,
		},

		"If checking a decrypted secret exists has an error we should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, fmt.Errorf("something"))
			},
			secret: "test",
			expErr: true,
		},

		"If encrypted and decrypted are present and no forceDecrypt is used, should ignore secret.": {
			forceDecrypt: false,
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(true, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret:    "test",
			expSecret: "",
		},

		"If encrypted and decrypted are present and forceDecrypt is used, should allow decrypt.": {
			forceDecrypt: true,
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(true, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret:    "test",
			expSecret: "test",
		},

		"If decrypted is missing and encrypted is missing should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(false, nil)
			},
			secret: "test",
			expErr: true,
		},

		"If decrypted is missing and encrypted is present should decrypt.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(true, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(false, nil)
			},
			secret:    "test",
			expSecret: "test",
		},

		"If decrypted is present, encrypted is missing and no forceDecrypt, should ignore.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret:    "test",
			expSecret: "",
		},

		"If decrypted is present, encrypted is missing and forceDecrypt, should error.": {
			forceDecrypt: true,
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret: "test",
			expErr: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks
			mr := &storagemock.SecretRepository{}
			test.mock(mr)

			p := process.NewDecryptionPathState(test.forceDecrypt, mr, log.Noop)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}

			mr.AssertExpectations(t)
		})
	}
}

func TestEncryptionPathState(t *testing.T) {
	tests := map[string]struct {
		ignoreBothExists bool
		mock             func(m *storagemock.SecretRepository)
		secret           string
		expSecret        string
		expErr           bool
	}{
		"If checking an encrypted secret exists has an error we should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, fmt.Errorf("something"))
			},
			secret: "test",
			expErr: true,
		},

		"If checking a decrypted secret exists has an error we should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, fmt.Errorf("something"))
			},
			secret: "test",
			expErr: true,
		},

		"If decrypted is present and encrypted is present should ignore.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(true, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret:    "test",
			expSecret: "",
		},

		"If decrypted is missing and encrypted is missing should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(false, nil)
			},
			secret: "test",
			expErr: true,
		},

		"If decrypted is missing and encrypted is present should ignore.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(true, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(false, nil)
			},
			secret:    "test",
			expSecret: "",
		},

		"If decrypted is present and encrypted is missing should decrypt.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret:    "test",
			expSecret: "test",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks
			mr := &storagemock.SecretRepository{}
			test.mock(mr)

			p := process.NewEncryptionPathState(mr, log.Noop)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}

			mr.AssertExpectations(t)
		})
	}
}

func TestEncryptedValidationPathState(t *testing.T) {
	tests := map[string]struct {
		mock      func(m *storagemock.SecretRepository)
		secret    string
		expSecret string
		expErr    bool
	}{
		"If checking an encrypted secret exists has an error we should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, fmt.Errorf("something"))
			},
			secret: "test",
			expErr: true,
		},

		"If checking a decrypted secret exists has an error we should fail.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, fmt.Errorf("something"))
			},
			secret: "test",
			expErr: true,
		},

		"If decrypted and encrypted is present it should error.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(true, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret: "test",
			expErr: true,
		},

		"If decrypted and not encrypted is present it should error.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(true, nil)
			},
			secret: "test",
			expErr: true,
		},

		"If not decrypted and not encrypted is present it should error.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(false, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(false, nil)
			},
			secret: "test",
			expErr: true,
		},

		"If not decrypted and encrypted is present it should allow.": {
			mock: func(m *storagemock.SecretRepository) {
				m.On("ExistsEncryptedSecret", mock.Anything, "test").Once().Return(true, nil)
				m.On("ExistsDecryptedSecret", mock.Anything, "test").Once().Return(false, nil)
			},
			secret:    "test",
			expSecret: "test",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			// Mocks
			mr := &storagemock.SecretRepository{}
			test.mock(mr)

			p := process.NewEncryptedValidationPathState(mr)
			gotSecret, err := p.ProcessID(context.TODO(), test.secret)

			if test.expErr {
				assert.Error(err)
			} else if assert.NoError(err) {
				assert.Equal(test.expSecret, gotSecret)
			}

			mr.AssertExpectations(t)
		})
	}
}
