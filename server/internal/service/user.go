package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/logmessager/server/internal/repository"
)

type UserService struct {
	userRepo *repository.UserRepository
}

func NewUserService(userRepo *repository.UserRepository) *UserService {
	return &UserService{userRepo: userRepo}
}

func (s *UserService) GetUser(ctx context.Context, userID uuid.UUID) (*repository.User, error) {
	return s.userRepo.GetByID(ctx, userID)
}

func (s *UserService) GetUserByUsername(ctx context.Context, username string) (*repository.User, error) {
	return s.userRepo.GetByUsername(ctx, username)
}

func (s *UserService) UpdatePresence(ctx context.Context, userID uuid.UUID, presence *repository.UserPresence) error {
	return s.userRepo.UpdatePresence(ctx, userID, presence)
}

func (s *UserService) GetPresence(ctx context.Context, userID uuid.UUID) (*repository.UserPresence, error) {
	return s.userRepo.GetPresence(ctx, userID)
}

func (s *UserService) ListOnlineUsers(ctx context.Context, limit, offset int) ([]repository.User, int, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}
	return s.userRepo.ListOnline(ctx, limit, offset)
}

func (s *UserService) SearchUsers(ctx context.Context, query string, limit int) ([]repository.User, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	return s.userRepo.SearchByUsername(ctx, query, limit)
}

type UserWithPresence struct {
	User     *repository.User
	Presence *repository.UserPresence
}

func (s *UserService) GetUserWithPresence(ctx context.Context, userID uuid.UUID) (*UserWithPresence, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	presence, err := s.userRepo.GetPresence(ctx, userID)
	if err != nil {
		return nil, err
	}

	return &UserWithPresence{
		User:     user,
		Presence: presence,
	}, nil
}
