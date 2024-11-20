package data

import (
	"encoding/hex"
	"github.com/arthures11/ripple/crypto"
	"sort"
)

func Sign(s Signable, public string, private string) error {

	publicK, _ := hex.DecodeString(public)

	s.InitialiseForSigning()
	copy(s.GetPublicKey().Bytes(), publicK)
	hash, _, err := SigningHash(s)
	if err != nil {
		return err
	}
	sig, err := crypto.Sign(private, hash.Bytes())
	if err != nil {
		return err
	}
	*s.GetSignature() = sig
	hash, _, err = Raw(s)
	if err != nil {
		return err
	}
	copy(s.GetHash().Bytes(), hash.Bytes())
	return nil
}

func CheckSignature(s Signable) (bool, error) {
	hash, msg, err := SigningHash(s)
	if err != nil {
		return false, err
	}
	return crypto.Verify(s.GetPublicKey().Bytes(), hash.Bytes(), msg, s.GetSignature().Bytes())
}

func SetSigners(s MultiSignable, signers ...Signer) error {
	sort.Slice(signers, func(i, j int) bool {
		return signers[i].Signer.Account.Less(signers[j].Signer.Account)
	})
	s.SetSigners(signers)

	hash, _, err := Raw(s)
	if err != nil {
		return err
	}
	copy(s.GetHash().Bytes(), hash.Bytes())
	return nil
}
