package grpc

import (
	"context"

	"github.com/google/uuid"
	pb "github.com/logmessager/proto/gen"
	"github.com/logmessager/server/internal/service"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type SessionServer struct {
	pb.UnimplementedSessionServiceServer
	sessionService *service.SessionService
}

func NewSessionServer(sessionService *service.SessionService) *SessionServer {
	return &SessionServer{sessionService: sessionService}
}

func RegisterSessionServer(s *grpc.Server, sessionService *service.SessionService) {
	pb.RegisterSessionServiceServer(s, NewSessionServer(sessionService))
}

func (s *SessionServer) RequestChat(ctx context.Context, req *pb.RequestChatRequest) (*pb.RequestChatResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	targetID, err := uuid.Parse(req.TargetUserId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid target user id")
	}

	chatReq, err := s.sessionService.RequestChat(ctx, userID, targetID)
	if err != nil {
		switch err {
		case service.ErrUserOffline:
			return nil, status.Error(codes.FailedPrecondition, "user is offline")
		case service.ErrAlreadyInSession:
			return nil, status.Error(codes.FailedPrecondition, "user already in active session")
		case service.ErrCannotChatWithSelf:
			return nil, status.Error(codes.InvalidArgument, "cannot chat with yourself")
		default:
			return nil, status.Error(codes.Internal, "failed to create chat request")
		}
	}

	return &pb.RequestChatResponse{
		RequestId: chatReq.ID.String(),
		Status:    pb.RequestStatus_REQUEST_STATUS_PENDING,
	}, nil
}

func (s *SessionServer) AcceptChat(ctx context.Context, req *pb.AcceptChatRequest) (*pb.AcceptChatResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	requestID, err := uuid.Parse(req.RequestId)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid request id: %s", req.RequestId)
	}

	_, responderEvent, err := s.sessionService.AcceptChat(ctx, requestID, userID)
	if err != nil {
		switch err {
		case service.ErrRequestNotFound:
			return nil, status.Error(codes.NotFound, "chat request not found")
		case service.ErrRequestExpired:
			return nil, status.Error(codes.FailedPrecondition, "chat request expired")
		case service.ErrNoConnectionPath:
			return nil, status.Error(codes.FailedPrecondition, "no connection path available")
		default:
			return nil, status.Error(codes.Internal, "failed to accept chat")
		}
	}

	role := pb.Role_ROLE_CLIENT
	if responderEvent.IsHost {
		role = pb.Role_ROLE_HOST
	}

	return &pb.AcceptChatResponse{
		Session: &pb.SessionInfo{
			SessionId:      responderEvent.SessionID.String(),
			HostUserId:     responderEvent.HostUserID.String(),
			PeerPublicKey:  responderEvent.PeerPublicKey,
			SessionToken:   responderEvent.SessionToken,
			ConnectionType: pb.ConnectionType_CONNECTION_TYPE_DIRECT,
			MyRole:         role,
			PeerUsername:   responderEvent.PeerUsername,
		},
	}, nil
}

func (s *SessionServer) DeclineChat(ctx context.Context, req *pb.DeclineChatRequest) (*pb.DeclineChatResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	requestID, err := uuid.Parse(req.RequestId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid request id")
	}

	if err := s.sessionService.DeclineChat(ctx, requestID, userID); err != nil {
		switch err {
		case service.ErrRequestNotFound:
			return nil, status.Error(codes.NotFound, "chat request not found")
		case service.ErrRequestExpired:
			return nil, status.Error(codes.FailedPrecondition, "chat request already handled")
		default:
			return nil, status.Error(codes.Internal, "failed to decline chat")
		}
	}

	return &pb.DeclineChatResponse{Success: true}, nil
}

func (s *SessionServer) EndSession(ctx context.Context, req *pb.EndSessionRequest) (*pb.EndSessionResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid session id")
	}

	reason := req.Reason.String()
	if reason == "" || reason == "END_REASON_UNSPECIFIED" {
		reason = "user_left"
	}

	if err := s.sessionService.EndSession(ctx, sessionID, userID, reason); err != nil {
		return nil, status.Error(codes.Internal, "failed to end session")
	}

	return &pb.EndSessionResponse{Success: true}, nil
}

func (s *SessionServer) ReportHostReady(ctx context.Context, req *pb.ReportHostReadyRequest) (*pb.ReportHostReadyResponse, error) {
	userID, ok := GetUserID(ctx)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "user not authenticated")
	}

	sessionID, err := uuid.Parse(req.SessionId)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid session id")
	}

	if req.ListenAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "listen address required")
	}

	if err := s.sessionService.ReportHostReady(ctx, sessionID, userID, req.ListenAddress); err != nil {
		return nil, status.Error(codes.Internal, "failed to report host ready")
	}

	return &pb.ReportHostReadyResponse{Success: true}, nil
}

func (s *SessionServer) GetSessionInfo(ctx context.Context, req *pb.GetSessionInfoRequest) (*pb.GetSessionInfoResponse, error) {
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (s *SessionServer) SubscribeSessionEvents(req *pb.SubscribeSessionEventsRequest, stream pb.SessionService_SubscribeSessionEventsServer) error {
	userID, ok := GetUserID(stream.Context())
	if !ok {
		return status.Error(codes.Unauthenticated, "user not authenticated")
	}

	eventCh := s.sessionService.Subscribe(userID)
	defer s.sessionService.Unsubscribe(userID)

	for {
		select {
		case event, ok := <-eventCh:
			if !ok {
				return nil
			}

			protoEvent := convertSessionEvent(event)
			if protoEvent != nil {
				if err := stream.Send(protoEvent); err != nil {
					return err
				}
			}

		case <-stream.Context().Done():
			return nil
		}
	}
}

func convertSessionEvent(event service.SessionEvent) *pb.SessionEvent {
	switch event.Type {
	case "chat_request":
		if payload, ok := event.Payload.(service.ChatRequestEvent); ok {
			return &pb.SessionEvent{
				Event: &pb.SessionEvent_ChatRequest{
					ChatRequest: &pb.ChatRequest{
						RequestId:    payload.RequestID.String(),
						FromUserId:   payload.FromUserID.String(),
						FromUsername: payload.FromUsername,
					},
				},
			}
		}
	case "session_started":
		if payload, ok := event.Payload.(*service.SessionStartedEvent); ok {
			role := pb.Role_ROLE_CLIENT
			if payload.IsHost {
				role = pb.Role_ROLE_HOST
			}
			return &pb.SessionEvent{
				Event: &pb.SessionEvent_SessionStarted{
					SessionStarted: &pb.SessionStarted{
						Session: &pb.SessionInfo{
							SessionId:     payload.SessionID.String(),
							HostUserId:    payload.HostUserID.String(),
							PeerPublicKey: payload.PeerPublicKey,
							SessionToken:  payload.SessionToken,
							MyRole:        role,
							PeerUsername:  payload.PeerUsername,
						},
					},
				},
			}
		}
	case "session_ended":
		if payload, ok := event.Payload.(service.SessionEndedEvent); ok {
			return &pb.SessionEvent{
				Event: &pb.SessionEvent_SessionEnded{
					SessionEnded: &pb.SessionEnded{
						SessionId: payload.SessionID.String(),
					},
				},
			}
		}
	case "host_ready":
		if payload, ok := event.Payload.(service.HostReadyEvent); ok {
			return &pb.SessionEvent{
				Event: &pb.SessionEvent_HostReady{
					HostReady: &pb.HostReady{
						SessionId:   payload.SessionID.String(),
						HostAddress: payload.HostAddress,
					},
				},
			}
		}
	}
	return nil
}
