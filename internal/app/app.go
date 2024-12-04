package app

import (
	grpcapp "github.com/aleksey3535/authGRPC/internal/app/grpc"
	authservice "github.com/aleksey3535/authGRPC/internal/services/auth"
	"github.com/aleksey3535/authGRPC/internal/storage/sqlite"
	"log/slog"
	"time"
)

type App struct {
	GRPCSrv *grpcapp.App
}

func New(log *slog.Logger, grpcPort int, storagePath string, tokenTTL time.Duration) *App {
	storage, err := sqlite.New(storagePath)
	if err != nil {
		panic(err)
	}
	authService := authservice.New(log, storage, storage, storage,tokenTTL)
	grpcApp := grpcapp.New(log,authService, grpcPort)
	return &App{
		GRPCSrv: grpcApp,
	}


}