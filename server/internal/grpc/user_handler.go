package grpc

import (
	"context"

	"github.com/google/uuid"
	pb "github.com/logmessager/proto/gen"
	"github.com/logmessager/server/internal/repository"
	"github.com/logmessager/server/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type UserServer struct {
	pb.UnimplementedUserServiceServer
	userService *service.UserService
	userRepo    *repository.UserRepository
	contactRepo *repository.ContactRepository
}

func NewUserServer(userService *service.UserService, userRepo *repository.UserRepository, contactRepo *repository.ContactRepository) *UserServer {
	return &UserServer{
		userService: userService,
		userRepo:    userRepo,
		contactRepo: contactRepo,
	}
}

func RegisterUserServer(s *grpc.Server, userService *service.UserService, userRepo *repository.UserRepository, contactRepo *repository.ContactRepository) {
	pb.RegisterUserServiceServer(s, NewUserServer(userService, userRepo, contactRepo))
}

func (s *UserServer) GetUser(ctx context.Context, req *pb.GetUserRequest) (*pb.GetUserResponse, error) {
	var user *repository.User
	var err error

	switch id := req.Identifier.(type) {
	case *pb.GetUserRequest_UserId:
		userID, parseErr := uuid.Parse(id.UserId)
		if parseErr != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid user id")
		}
		user, err = s.userService.GetUser(ctx, userID)
	case *pb.GetUserRequest_Username:
		user, err = s.userService.GetUserByUsername(ctx, id.Username)
	default:
		return nil, status.Error(codes.InvalidArgument, "user_id or username required")
	}

	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to get user")
	}

	presence, _ := s.userService.GetPresence(ctx, user.ID)

	return &pb.GetUserResponse{
		User: &pb.UserInfo{
			Id:       user.ID.String(),
			Username: user.Username,
			IsOnline: presence != nil && presence.IsOnline,
			LastSeen: func() int64 {
				if presence != nil {
					return presence.LastSeen.Unix()
				}
				return 0
			}(),
		},
	}, nil
}

func (s *UserServer) GetPublicKey(ctx context.Context, req *pb.GetPublicKeyRequest) (*pb.GetPublicKeyResponse, error) {
	userID, err := uuid.Parse(req.UserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid user id")
	}

	pk, err := s.userService.GetPublicKey(ctx, userID)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to get public key")
	}

	return &pb.GetPublicKeyResponse{
		PublicKey: pk.PublicKey,
		KeyType:   pk.KeyType,
	}, nil
}

func (s *UserServer) UpdatePresence(ctx context.Context, req *pb.UpdatePresenceRequest) (*pb.UpdatePresenceResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	presence := &repository.UserPresence{
		UserID:   userID,
		IsOnline: req.IsOnline,
	}

	if req.Network != nil {
		presence.CanAcceptInbound = req.Network.CanAcceptInbound
		presence.PublicAddress = req.Network.PublicAddress
		presence.NatType = req.Network.NatType.String()
	}

	if err := s.userService.UpdatePresence(ctx, userID, presence); err != nil {
		return nil, status.Error(codes.Internal, "failed to update presence")
	}

	return &pb.UpdatePresenceResponse{Success: true}, nil
}

func (s *UserServer) ListOnlineUsers(ctx context.Context, req *pb.ListOnlineUsersRequest) (*pb.ListOnlineUsersResponse, error) {
	users, total, err := s.userService.ListOnlineUsers(ctx, int(req.Limit), int(req.Offset))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list users")
	}

	protoUsers := make([]*pb.UserInfo, len(users))
	for i, u := range users {
		protoUsers[i] = &pb.UserInfo{
			Id:       u.ID.String(),
			Username: u.Username,
			IsOnline: true,
		}
	}

	return &pb.ListOnlineUsersResponse{
		Users: protoUsers,
		Total: int32(total),
	}, nil
}

func (s *UserServer) SearchUsers(ctx context.Context, req *pb.SearchUsersRequest) (*pb.SearchUsersResponse, error) {
	if req.Query == "" {
		return nil, status.Error(codes.InvalidArgument, "query required")
	}

	users, err := s.userService.SearchUsers(ctx, req.Query, int(req.Limit))
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to search users")
	}

	protoUsers := make([]*pb.UserInfo, len(users))
	for i, u := range users {
		presence, _ := s.userService.GetPresence(ctx, u.ID)
		protoUsers[i] = &pb.UserInfo{
			Id:       u.ID.String(),
			Username: u.Username,
			IsOnline: presence != nil && presence.IsOnline,
		}
	}

	return &pb.SearchUsersResponse{Users: protoUsers}, nil
}

func (s *UserServer) SubscribePresence(req *pb.SubscribePresenceRequest, stream pb.UserService_SubscribePresenceServer) error {
	// TODO: Implement presence subscription
	return status.Error(codes.Unimplemented, "not implemented")
}

func (s *UserServer) AddContact(ctx context.Context, req *pb.AddContactRequest) (*pb.AddContactResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	if req.Username == "" {
		return nil, status.Error(codes.InvalidArgument, "username required")
	}

	// Find user by username
	contactUser, err := s.userService.GetUserByUsername(ctx, req.Username)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "failed to find user")
	}

	// Create contact
	contact, err := s.contactRepo.Create(ctx, userID, contactUser.ID, req.Nickname)
	if err != nil {
		switch err {
		case repository.ErrCannotAddSelf:
			return nil, status.Error(codes.InvalidArgument, "cannot add yourself as contact")
		case repository.ErrContactExists:
			return nil, status.Error(codes.AlreadyExists, "contact already exists")
		default:
			return nil, status.Error(codes.Internal, "failed to add contact")
		}
	}

	// Get presence info
	presence, _ := s.userService.GetPresence(ctx, contactUser.ID)
	isOnline := presence != nil && presence.IsOnline
	var lastSeen int64
	if presence != nil {
		lastSeen = presence.LastSeen.Unix()
	}

	nickname := req.Nickname
	if contact.Nickname.Valid {
		nickname = contact.Nickname.String
	}

	return &pb.AddContactResponse{
		Contact: &pb.Contact{
			Id:       contact.ID.String(),
			UserId:   contactUser.ID.String(),
			Username: contactUser.Username,
			Nickname: nickname,
			IsOnline: isOnline,
			LastSeen: lastSeen,
		},
	}, nil
}

func (s *UserServer) RemoveContact(ctx context.Context, req *pb.RemoveContactRequest) (*pb.RemoveContactResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	contactID, err := uuid.Parse(req.ContactId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid contact id")
	}

	if err := s.contactRepo.Delete(ctx, userID, contactID); err != nil {
		if err == repository.ErrContactNotFound {
			return nil, status.Error(codes.NotFound, "contact not found")
		}
		return nil, status.Error(codes.Internal, "failed to remove contact")
	}

	return &pb.RemoveContactResponse{Success: true}, nil
}

func (s *UserServer) ListContacts(ctx context.Context, req *pb.ListContactsRequest) (*pb.ListContactsResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	contacts, err := s.contactRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, status.Error(codes.Internal, "failed to list contacts")
	}

	protoContacts := make([]*pb.Contact, len(contacts))
	for i, c := range contacts {
		nickname := ""
		if c.Nickname.Valid {
			nickname = c.Nickname.String
		}
		protoContacts[i] = &pb.Contact{
			Id:       c.ID.String(),
			UserId:   c.ContactUserID.String(),
			Username: c.Username,
			Nickname: nickname,
			IsOnline: c.IsOnline,
			LastSeen: c.LastSeen.Unix(),
		}
	}

	return &pb.ListContactsResponse{Contacts: protoContacts}, nil
}
