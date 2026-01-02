package grpc

import (
	"context"
	"strings"

	"github.com/google/uuid"
	"github.com/logmessager/server/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type contextKey string

const (
	UserIDKey   contextKey = "user_id"
	UsernameKey contextKey = "username"
)

// Methods that don't require authentication
var publicMethods = map[string]bool{
	"/logmessager.auth.v1.AuthService/Register":     true,
	"/logmessager.auth.v1.AuthService/Login":        true,
	"/logmessager.auth.v1.AuthService/RefreshToken": true,
}

type AuthInterceptor struct {
	authService *service.AuthService
}

func NewAuthInterceptor(authService *service.AuthService) *AuthInterceptor {
	return &AuthInterceptor{authService: authService}
}

func (i *AuthInterceptor) Unary() grpc.UnaryServerInterceptor {
	return func(
		ctx context.Context,
		req interface{},
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (interface{}, error) {
		// Skip auth for public methods
		if publicMethods[info.FullMethod] {
			return handler(ctx, req)
		}

		// Authenticate
		newCtx, err := i.authenticate(ctx)
		if err != nil {
			return nil, err
		}

		return handler(newCtx, req)
	}
}

func (i *AuthInterceptor) Stream() grpc.StreamServerInterceptor {
	return func(
		srv interface{},
		ss grpc.ServerStream,
		info *grpc.StreamServerInfo,
		handler grpc.StreamHandler,
	) error {
		// Skip auth for public methods
		if publicMethods[info.FullMethod] {
			return handler(srv, ss)
		}

		// Authenticate
		newCtx, err := i.authenticate(ss.Context())
		if err != nil {
			return err
		}

		// Wrap stream with new context
		wrapped := &wrappedStream{
			ServerStream: ss,
			ctx:          newCtx,
		}

		return handler(srv, wrapped)
	}
}

func (i *AuthInterceptor) authenticate(ctx context.Context) (context.Context, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "missing metadata")
	}

	values := md.Get("authorization")
	if len(values) == 0 {
		return nil, status.Error(codes.Unauthenticated, "missing authorization header")
	}

	token := values[0]
	token = strings.TrimPrefix(token, "Bearer ")

	claims, err := i.authService.ValidateToken(ctx, token)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid token")
	}

	userID, err := uuid.Parse(claims.UserID)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated, "invalid user id in token")
	}

	// Add user info to context
	newCtx := context.WithValue(ctx, UserIDKey, userID)
	newCtx = context.WithValue(newCtx, UsernameKey, claims.Username)

	return newCtx, nil
}

// Helper functions to extract user info from context
func GetUserID(ctx context.Context) (uuid.UUID, bool) {
	userID, ok := ctx.Value(UserIDKey).(uuid.UUID)
	return userID, ok
}

func GetUsername(ctx context.Context) (string, bool) {
	username, ok := ctx.Value(UsernameKey).(string)
	return username, ok
}

// wrappedStream wraps grpc.ServerStream to override Context()
type wrappedStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (w *wrappedStream) Context() context.Context {
	return w.ctx
}
