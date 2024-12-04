package grpcapp

import (
	authgrpc "github.com/aleksey3535/authGRPC/internal/grpc/auth"
	"fmt"
	"log/slog"
	"net"

	"google.golang.org/grpc"
)

type App struct {
	log 		*slog.Logger
	gRPCServer 	*grpc.Server
	port 		int	
}

func New(log *slog.Logger, authService authgrpc.Auth,  port int) *App {
	gRPCServer := grpc.NewServer()
	authgrpc.Register(gRPCServer, authService)
	return &App{
		log: log, 
		gRPCServer: gRPCServer,
		 port: port,
		}	
}

func(a *App) MustRun() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func(a *App) Run() error {
	const op = "grpcapp.Run"
	log := a.log.With(
		slog.String("op", op),
		slog.Int("port", a.port),
	)
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", a.port))
	if err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	log.Info("starting gRPC server", slog.String("addr", l.Addr().String()))
	if err := a.gRPCServer.Serve(l); err != nil {
		return fmt.Errorf("%s: %w", op, err)
	}
	return nil
}

func(a *App) Stop() {
	const op = "grpcapp.Stop"
	a.log.With(slog.String("op", op)).Info("stopping gRPC server", slog.Int("port", a.port))
	a.gRPCServer.GracefulStop() 
}