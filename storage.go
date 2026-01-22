package nanoca

import (
	"context"
	"time"
)

type Storage interface {
	CreateNonce(ctx context.Context, nonce *Nonce) error
	ConsumeNonce(ctx context.Context, value string, expiry time.Duration) (*Nonce, error)

	CreateAccount(ctx context.Context, account *Account) error
	GetAccount(ctx context.Context, id string) (*Account, error)
	GetAccountByKey(ctx context.Context, keyThumbprint string) (*Account, error)
	UpdateAccount(ctx context.Context, account *Account) error

	CreateOrder(ctx context.Context, order *Order) error
	GetOrder(ctx context.Context, id string) (*Order, error)
	UpdateOrder(ctx context.Context, order *Order) error
	GetOrdersByAccount(ctx context.Context, accountID string) ([]*Order, error)

	CreateAuthorization(ctx context.Context, authz *Authorization) error
	GetAuthorization(ctx context.Context, id string) (*Authorization, error)
	UpdateAuthorization(ctx context.Context, authz *Authorization) error

	CreateChallenge(ctx context.Context, challenge *Challenge) error
	GetChallenge(ctx context.Context, id string) (*Challenge, error)
	SetChallengeProcessing(ctx context.Context, id string) error
	SetChallengeValid(ctx context.Context, id string, validated time.Time, attestation map[string]any) error
	SetChallengeInvalid(ctx context.Context, id string, validated time.Time, problem *Problem) error

	CreateCertificate(ctx context.Context, cert *Certificate) error
	GetCertificate(ctx context.Context, id string) (*Certificate, error)

	Close() error
}
