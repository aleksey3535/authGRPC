package suite

import (
	"github.com/aleksey3535/authGRPC/internal/config"
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/aleksey3535/protos/gen/go/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type Suite struct {
	*testing.T
	Cfg 		*config.Config
	AuthClient	auth.AuthClient
	TimeOut 	time.Duration
}

const (
	grpcHost = "localhost"
)

func New(t *testing.T) (context.Context, *Suite) {
	t.Helper()
	t.Parallel()
	cfg := config.MustLoadByPath("../config/local.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), cfg.GRPC.Timeout)
	t.Cleanup(func ()  {
		t.Helper()
		cancel()
	})
	conn, err := grpc.NewClient(grpcAddress(cfg), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc server connection failed: %v", err)	
	}
	return ctx, &Suite{
		T:			t,
		Cfg: 		cfg,
		AuthClient: auth.NewAuthClient(conn),
	}
	
	
}

func grpcAddress(cfg *config.Config) string {
	return net.JoinHostPort(grpcHost, strconv.Itoa(cfg.GRPC.Port))
}