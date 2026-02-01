package grpc

import (
	"context"

	pb "github.com/logmessager/proto/gen"
	"github.com/logmessager/server/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthServer struct {
	pb.UnimplementedAuthServiceServer
	authService *service.AuthService
}

func NewAuthServer(authService *service.AuthService) *AuthServer {
	return &AuthServer{authService: authService}
}

func RegisterAuthServer(s *grpc.Server, authService *service.AuthService) {
	pb.RegisterAuthServiceServer(s, NewAuthServer(authService))
}

func (s *AuthServer) Register(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password required")
	}

	if len(req.EncryptionPublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "encryption public key required")
	}

	if len(req.SignaturePublicKey) == 0 {
		return nil, status.Error(codes.InvalidArgument, "signature public key required")
	}

	user, err := s.authService.Register(ctx, req.Username, req.Password, req.EncryptionPublicKey, req.SignaturePublicKey)
	if err != nil {
		switch err {
		case service.ErrUsernameTaken:
			return nil, status.Error(codes.AlreadyExists, err.Error())
		case service.ErrWeakPassword, service.ErrInvalidUsername:
			return nil, status.Error(codes.InvalidArgument, err.Error())
		default:
			// Log the actual error for debugging
			return nil, status.Errorf(codes.Internal, "failed to register user: %v", err)
		}
	}

	return &pb.RegisterResponse{
		UserId:   user.ID.String(),
		Username: user.Username,
	}, nil
}

func (s *AuthServer) Login(ctx context.Context, req *pb.LoginRequest) (*pb.LoginResponse, error) {
	if req.Username == "" || req.Password == "" {
		return nil, status.Error(codes.InvalidArgument, "username and password required")
	}

	result, err := s.authService.Login(ctx, req.Username, req.Password)
	if err != nil {
		if err == service.ErrInvalidCredentials {
			return nil, status.Error(codes.Unauthenticated, "invalid credentials")
		}
		return nil, status.Error(codes.Internal, "failed to login")
	}

	return &pb.LoginResponse{
		AccessToken:  result.AccessToken,
		RefreshToken: result.RefreshToken,
		ExpiresAt:    result.ExpiresAt.Unix(),
		User: &pb.User{
			Id:        result.User.ID.String(),
			Username:  result.User.Username,
			CreatedAt: result.User.CreatedAt.Unix(),
		},
	}, nil
}

func (s *AuthServer) RefreshToken(ctx context.Context, req *pb.RefreshTokenRequest) (*pb.RefreshTokenResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token required")
	}

	accessToken, expiresAt, err := s.authService.RefreshToken(ctx, req.RefreshToken)
	if err != nil {
		if err == service.ErrInvalidToken {
			return nil, status.Error(codes.Unauthenticated, "invalid or expired refresh token")
		}
		return nil, status.Error(codes.Internal, "failed to refresh token")
	}

	return &pb.RefreshTokenResponse{
		AccessToken: accessToken,
		ExpiresAt:   expiresAt.Unix(),
	}, nil
}

func (s *AuthServer) Logout(ctx context.Context, req *pb.LogoutRequest) (*pb.LogoutResponse, error) {
	if req.RefreshToken == "" {
		return nil, status.Error(codes.InvalidArgument, "refresh token required")
	}

	_ = s.authService.Logout(ctx, req.RefreshToken)
	return &pb.LogoutResponse{Success: true}, nil
}
