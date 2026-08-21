// Package application defines the one typed UI/timer application boundary.
package application

import (
	"context"
	"fmt"
	"lanpanel/internal/domain"
	"reflect"
	"sort"
)

type ActorKind string

const (
	ActorUI    ActorKind = "ui"
	ActorTimer ActorKind = "timer"
)

type Actor struct {
	Kind       ActorKind
	Identity   string
	Generation uint64
}
type Call struct {
	Operation domain.OperationCode
	Target    domain.OperationTarget
	Payload   any
}
type Result struct {
	Operation domain.OperationCode
	Target    domain.OperationTarget
	JobID     string
	Payload   any
}
type (
	Handler      func(context.Context, Actor, Call) (Result, error)
	registration struct {
		operation domain.OperationCode
		payload   reflect.Type
		ui, timer bool
		handler   Handler
	}
)
type Registration struct{ value registration }

func RegisterAction(operation domain.OperationCode, payload any, ui, timer bool, handler Handler) (Registration, error) {
	if _, err := domain.ParseOperationCode(string(operation)); err != nil || payload == nil || handler == nil || !ui && !timer {
		return Registration{}, fmt.Errorf("application action registration is incomplete")
	}
	return Registration{registration{operation, reflect.TypeOf(payload), ui, timer, handler}}, nil
}

type Service struct {
	handlers map[domain.OperationCode]registration
}

func New(registrations []Registration) (*Service, error) {
	service := &Service{handlers: map[domain.OperationCode]registration{}}
	for _, item := range registrations {
		value := item.value
		if value.operation == "" || value.payload == nil || value.handler == nil {
			return nil, fmt.Errorf("application action registration is incomplete")
		}
		if _, ok := service.handlers[value.operation]; ok {
			return nil, fmt.Errorf("application action is registered twice")
		}
		service.handlers[value.operation] = value
	}
	return service, nil
}

func (service *Service) Available(actor Actor) []domain.OperationCode {
	result := []domain.OperationCode{}
	if service == nil {
		return result
	}
	for operation, entry := range service.handlers {
		if actor.Kind == ActorUI && entry.ui || actor.Kind == ActorTimer && entry.timer {
			result = append(result, operation)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func (service *Service) Invoke(ctx context.Context, actor Actor, call Call) (Result, error) {
	if service == nil || actor.Identity == "" || actor.Generation == 0 || actor.Kind != ActorUI && actor.Kind != ActorTimer {
		return Result{}, fmt.Errorf("application actor is invalid")
	}
	if err := domain.ValidateOperationTarget(call.Operation, call.Target); err != nil {
		return Result{}, err
	}
	entry, ok := service.handlers[call.Operation]
	if !ok {
		return Result{}, ErrUnavailable
	}
	if actor.Kind == ActorUI && !entry.ui || actor.Kind == ActorTimer && !entry.timer {
		return Result{}, ErrUnavailable
	}
	if reflect.TypeOf(call.Payload) != entry.payload {
		return Result{}, fmt.Errorf("application payload type mismatched")
	}
	result, err := entry.handler(ctx, actor, call)
	if err != nil {
		return Result{}, err
	}
	if result.Operation != call.Operation || result.Target != call.Target {
		return Result{}, fmt.Errorf("application result identity mismatched")
	}
	return result, nil
}

var ErrUnavailable = fmt.Errorf("action_unavailable")
