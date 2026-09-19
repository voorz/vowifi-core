package imscore

import (
	"context"
	"fmt"
	"sync"

	"github.com/voorz/sipgo"
	"github.com/voorz/sipgo/sip"
)

// doTransaction sends a SIP request via the imscore-owned sipClient and waits
// for the first response. This is the imscore-owned version of
// voiceclient.Client.doTransaction, moved here as part of the architecture
// refactoring.
func (s *Service) doTransaction(ctx context.Context, req *sip.Request, opts ...sipgo.ClientRequestOption) (*sip.Response, error) {
	if s.sipClient == nil {
		return nil, fmt.Errorf("imscore: SIP client unavailable")
	}
	tx, err := s.sipClient.TransactionRequest(ctx, req, opts...)
	if err != nil {
		return nil, err
	}
	var terminateOnce sync.Once
	terminate := func() { terminateOnce.Do(func() { tx.Terminate() }) }
	defer terminate()

	select {
	case <-tx.Done():
		if err := tx.Err(); err != nil {
			return nil, fmt.Errorf("transaction ended: %w", err)
		}
		return nil, fmt.Errorf("transaction ended without a response")
	case res := <-tx.Responses():
		return res, nil
	case <-ctx.Done():
		terminate()
		return nil, ctx.Err()
	}
}

// doRegisterTransaction sends a REGISTER request with the standard register
// transaction timeout.
func (s *Service) doRegisterTransaction(ctx context.Context, req *sip.Request, opts ...sipgo.ClientRequestOption) (*sip.Response, error) {
	txCtx, cancel := context.WithTimeout(ctx, registerTransactionTimeout)
	defer cancel()
	return s.doTransaction(txCtx, req, opts...)
}

// doTransactionFinal sends a SIP request and waits for a non-provisional
// (non-1xx) final response. Used for INVITE and other dialog-initiating
// requests where provisional responses like 100 Trying / 183 Session Progress
// are expected before the final 2xx/3xx/4xx/5xx/6xx.
//
// This is the imscore-owned version of voiceclient.Client.doTransactionFinal.
func (s *Service) doTransactionFinal(ctx context.Context, req *sip.Request) (*sip.Response, error) {
	if s.sipClient == nil {
		return nil, fmt.Errorf("imscore: SIP client unavailable")
	}
	tx, err := s.sipClient.TransactionRequest(ctx, req)
	if err != nil {
		return nil, err
	}
	var terminateOnce sync.Once
	terminate := func() { terminateOnce.Do(func() { tx.Terminate() }) }
	defer terminate()

	for {
		select {
		case <-tx.Done():
			if err := tx.Err(); err != nil {
				return nil, fmt.Errorf("transaction ended: %w", err)
			}
			return nil, fmt.Errorf("transaction ended without a final response")
		case res := <-tx.Responses():
			if res.IsProvisional() {
				continue
			}
			return res, nil
		case <-ctx.Done():
			terminate()
			return nil, ctx.Err()
		}
	}
}
