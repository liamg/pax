package pax

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Crypto(t *testing.T) {

	input := []byte("this is a test")
	key := []byte("dsf0wad5373is7d7")

	enc, err := encrypt(input, key)
	require.NoError(t, err)

	dec, err := decrypt(enc, key)
	require.NoError(t, err)

	assert.Equal(t, input, dec)

}
