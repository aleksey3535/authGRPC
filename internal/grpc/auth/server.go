package auth

import (
	authservice "github.com/aleksey3535/authGRPC/internal/services/auth"
	"context"
	"errors"

	"github.com/aleksey3535/protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Auth interface {
	Login(ctx context.Context, email, password string, appId int) (token string, err error)
	RegisterNewUser(ctx context.Context, email, password string) (userID int64, err error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}


type serverApi struct {
	auth.UnimplementedAuthServer
	AuthService Auth
}

func Register(gRPC *grpc.Server, authService Auth) {
	auth.RegisterAuthServer(gRPC, &serverApi{AuthService: authService})
}

const (
	emptyEmail = ""
	emptyPassword = ""
	emptyValue = 0

)

func (s *serverApi) Login(ctx context.Context, req *auth.LoginRequest) (*auth.LoginResponse, error) {
	if err := validateLoginRequest(req); err != nil {
		return nil, err
	}
	token, err := s.AuthService.Login(ctx, req.GetEmail(), req.GetPassword(), int(req.GetAppId()))
	if err != nil {
		if errors.Is(err, authservice.ErrInvalidCredentials) {
			return nil, status.Error(codes.InvalidArgument, "invalid argument")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &auth.LoginResponse{
		Token: token,
	}, nil
}



func(s *serverApi) Register(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	if err := validateRegisterRequest(req); err != nil {
		return nil, err
	}
	userID, err := s.AuthService.RegisterNewUser(ctx, req.GetEmail(), req.GetPasword())
	if err != nil {
		if errors.Is(err, authservice.ErrUserExists) {
			return nil, status.Error(codes.AlreadyExists, "user already exists")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &auth.RegisterResponse{
		UserId: userID,
	}, nil
}

func(s *serverApi) IsAdmin(ctx context.Context, req *auth.IsAdminRequest) (*auth.IsAdminResponse, error) {
	if err := validateIsAdminRequest(req); err != nil {
		return nil, err
	}
	isAdmin, err := s.AuthService.IsAdmin(ctx, req.GetUserId())
	if err != nil {
		if errors.Is(err, authservice.ErrInvalidAppID) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Error(codes.Internal, "internal error")
	}
	return &auth.IsAdminResponse{
		IsAdmin: isAdmin,
	}, nil
}

func validateLoginRequest(req *auth.LoginRequest) error {
	if req.GetEmail() == emptyEmail {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPassword() == emptyPassword {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	if req.GetAppId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app id is required")
	}
	return nil
}

func validateRegisterRequest(req *auth.RegisterRequest) error {
	if req.GetEmail() == emptyEmail {
		return status.Error(codes.InvalidArgument, "email is required")
	}
	if req.GetPasword() == emptyPassword {
		return status.Error(codes.InvalidArgument, "password is required")
	}
	return nil
}

func validateIsAdminRequest(req *auth.IsAdminRequest) error {
	if req.GetUserId() == emptyValue {
		return status.Error(codes.InvalidArgument, "app id is required")
	}
	return nil
}