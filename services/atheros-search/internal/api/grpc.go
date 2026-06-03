package api

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/rs/zerolog"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/auth"
	"github.com/zlovtnik/ssl-proxy/services/atheros-search/internal/search"
	searchv1 "github.com/zlovtnik/ssl-proxy/services/atheros-search/proto/atheros/search/v1"
)

func StartGRPC(ctx context.Context, port int, svc *search.Service, tokenAuth *auth.TokenAuth, logger zerolog.Logger) (*grpc.Server, error) {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return nil, err
	}
	server := grpc.NewServer(
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.UnaryInterceptor(unaryAuth(tokenAuth)),
		grpc.StreamInterceptor(streamAuth(tokenAuth)),
	)
	searchv1.RegisterSearchServiceServer(server, svc)
	go func() {
		<-ctx.Done()
		server.GracefulStop()
	}()
	go func() {
		logger.Info().Int("port", port).Msg("grpc server listening")
		if err := server.Serve(listener); err != nil {
			logger.Error().Err(err).Msg("grpc server stopped")
		}
	}()
	return server, nil
}

func unaryAuth(tokenAuth *auth.TokenAuth) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if !authorized(ctx, tokenAuth) {
			return nil, status.Error(codes.Unauthenticated, "missing or invalid bearer token")
		}
		return handler(ctx, req)
	}
}

func streamAuth(tokenAuth *auth.TokenAuth) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if !authorized(stream.Context(), tokenAuth) {
			return status.Error(codes.Unauthenticated, "missing or invalid bearer token")
		}
		return handler(srv, stream)
	}
}

func authorized(ctx context.Context, tokenAuth *auth.TokenAuth) bool {
	if tokenAuth == nil || !tokenAuth.Enabled() {
		return true
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return false
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return false
	}
	return tokenAuth.VerifyAuthorization(strings.Join(values, " "))
}
