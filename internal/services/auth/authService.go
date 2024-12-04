package authservice

import (
	"github.com/aleksey3535/authGRPC/internal/domain/models"
	"github.com/aleksey3535/authGRPC/internal/lib/jwt"
	"github.com/aleksey3535/authGRPC/internal/lib/logger/sl"
	"github.com/aleksey3535/authGRPC/internal/storage"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type AuthService struct {
	log 		*slog.Logger
	usrSaver 	UserSaver
	usrProvider UserProvider
	appProvider AppProvider
	tokenTTL 	time.Duration
}

func New(
	log *slog.Logger, usrSaver UserSaver,
	usrProvider UserProvider, appProvider AppProvider,
	tokenTTL time.Duration) *AuthService {
	return &AuthService{log: log, usrSaver: usrSaver, usrProvider: usrProvider, appProvider: appProvider, tokenTTL: tokenTTL}
}


type UserSaver interface {
	SaveUser(ctx context.Context, email string, passHash []byte) (userId int64, err error)
}

type UserProvider interface {
	User(ctx context.Context, email string) (models.User, error)
	IsAdmin(ctx context.Context, userID int64) (bool, error)
}

var (
	ErrInvalidCredentials 	= errors.New("invalid credentials")
	ErrInvalidAppID 		= errors.New("invalid app id")
	ErrUserExists			= errors.New("user already exists") 
)

type AppProvider interface {
	App(ctx context.Context, appID int) (models.App, error)
}


func(a *AuthService) Login(ctx context.Context, email string, password string, appID int) (string, error) {
	const op = "authService.Login"
	log := a.log.With(
		slog.String("op", op),
		slog.String("username", email),
	)
	log.Info("attempting to login user")
	user, err := a.usrProvider.User(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrUserNotFound) {
			a.log.Warn("user not found", sl.Err(err))
			return "", fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to get user", sl.Err(err))
		return "", fmt.Errorf("%s:%w", op, err)
	}
	if err := bcrypt.CompareHashAndPassword(user.PassHash, []byte(password)); err != nil {
		a.log.Info("invalid credentials", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, ErrInvalidCredentials)
	}
	app, err := a.appProvider.App(ctx, appID)
	if err != nil {
		return "", fmt.Errorf("%s: %w", op, err)
	}
	log.Info("user logged successfully")
	token, err := jwt.NewToken(user, app, a.tokenTTL)
	if err != nil {
		a.log.Error("failed to generate token", sl.Err(err))
		return "", fmt.Errorf("%s: %w", op, err)	
	}
	return token, nil
}

func(a *AuthService) RegisterNewUser(ctx context.Context, email string, password string) (int64, error) {
	const op = "authService.RegisterNewUser"
	log := a.log.With(
		slog.String("op", op),
		slog.String("email", email),
	)

	log.Info("registering user")
	passHash, err  := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to generate password hash", sl.Err(err))
		return 0, fmt.Errorf("%s:%w", op, err)
	}
	id, err := a.usrSaver.SaveUser(ctx, email, passHash)
	if err != nil {
		if errors.Is(err, storage.ErrUserExists) {
			log.Warn("user already exists", sl.Err(err))
			return 0, fmt.Errorf("%s: %w", op, ErrUserExists)
		}
		log.Error("failed to save user", sl.Err(err))
		return 0, fmt.Errorf("%s:%w", op, err)
	}
	log.Info("user registered")
	return id, nil 
}

func(a *AuthService) IsAdmin(ctx context.Context, userID int64) (bool, error) {
	const op = "authService.IsAdmin"
	log := a.log.With(
		slog.String("op", op),
		slog.Int64("user_id", userID),
	)
	log.Info("checking if user is admin")
	isAdmin, err := a.usrProvider.IsAdmin(ctx, userID)
	if err != nil {
 		if errors.Is(err, storage.ErrAppNotFound) {
			log.Warn("user not found", sl.Err(err))
			return false, fmt.Errorf("%s: %w", op, ErrInvalidAppID)
		}
		return false, fmt.Errorf("%s: %w", op, err)
	}
	log.Info("checked if user is admin", slog.Bool("is_admin", isAdmin))
	return isAdmin, nil
	
}

