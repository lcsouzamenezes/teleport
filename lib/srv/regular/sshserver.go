/*
Copyright 2015-2020 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package regular implements SSH server that supports multiplexing
// tunneling, SSH connections proxying and only supports Key based auth
package regular

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"sync"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/observability/tracing"
	tracessh "github.com/gravitational/teleport/api/observability/tracing/ssh"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/bpf"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/inventory"
	"github.com/gravitational/teleport/lib/labels"
	"github.com/gravitational/teleport/lib/limiter"
	"github.com/gravitational/teleport/lib/pam"
	restricted "github.com/gravitational/teleport/lib/restrictedsession"
	"github.com/gravitational/teleport/lib/reversetunnel"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local"
	rsession "github.com/gravitational/teleport/lib/session"
	"github.com/gravitational/teleport/lib/srv"
	"github.com/gravitational/teleport/lib/sshutils"
	"github.com/gravitational/teleport/lib/sshutils/x11"
	"github.com/gravitational/teleport/lib/teleagent"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/jonboulle/clockwork"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	semconv "go.opentelemetry.io/otel/semconv/v1.10.0"
	oteltrace "go.opentelemetry.io/otel/trace"
	"golang.org/x/crypto/ssh"
)

const sftpSubsystem = "sftp"

var (
	log = logrus.WithFields(logrus.Fields{
		trace.Component: teleport.ComponentNode,
	})

	userSessionLimitHitCount = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: teleport.MetricUserMaxConcurrentSessionsHit,
			Help: "Number of times a user exceeded their max concurrent ssh connections",
		},
	)
)

// Server implements SSH server that uses configuration backend and
// certificate-based authentication
type Server struct {
	sync.Mutex

	*logrus.Entry

	namespace string
	addr      utils.NetAddr
	hostname  string

	srv           *sshutils.Server
	shell         string
	getRotation   RotationGetter
	authService   srv.AccessPoint
	reg           *srv.SessionRegistry
	sessionServer rsession.Service
	limiter       *limiter.Limiter

	inventoryHandle inventory.DownstreamHandle

	// labels are static labels.
	labels map[string]string

	// dynamicLabels are the result of command execution.
	dynamicLabels *labels.Dynamic

	// cloudLabels are the labels imported from a cloud provider.
	cloudLabels labels.Importer

	proxyMode        bool
	proxyTun         reversetunnel.Tunnel
	proxyAccessPoint auth.ReadProxyAccessPoint
	peerAddr         string

	advertiseAddr   *utils.NetAddr
	proxyPublicAddr utils.NetAddr

	// server UUID gets generated once on the first start and never changes
	// usually stored in a file inside the data dir
	uuid string

	// this gets set to true for unit testing
	isTestStub bool

	// cancel cancels all operations
	cancel context.CancelFunc
	// ctx is broadcasting context closure
	ctx context.Context

	// StreamEmitter points to the auth service and emits audit events
	events.StreamEmitter

	// clock is a system clock
	clock clockwork.Clock

	// permitUserEnvironment controls if this server will read ~/.tsh/environment
	// before creating a new session.
	permitUserEnvironment bool

	// ciphers is a list of ciphers that the server supports. If omitted,
	// the defaults will be used.
	ciphers []string

	// kexAlgorithms is a list of key exchange (KEX) algorithms that the
	// server supports. If omitted, the defaults will be used.
	kexAlgorithms []string

	// macAlgorithms is a list of message authentication codes (MAC) that
	// the server supports. If omitted the defaults will be used.
	macAlgorithms []string

	// authHandlers are common authorization and authentication related handlers.
	authHandlers *srv.AuthHandlers

	// termHandlers are common terminal related handlers.
	termHandlers *srv.TermHandlers

	// pamConfig holds configuration for PAM.
	pamConfig *pam.Config

	// dataDir is a server local data directory
	dataDir string

	// heartbeat sends updates about this server
	// back to auth server
	heartbeat srv.HeartbeatI

	// useTunnel is used to inform other components that this server is
	// requesting connections to it come over a reverse tunnel.
	useTunnel bool

	// fips means Teleport started in a FedRAMP/FIPS 140-2 compliant
	// configuration.
	fips bool

	// ebpf is the service used for enhanced session recording.
	ebpf bpf.BPF

	// restrictedMgr is the service used for restricting access to kernel objects
	restrictedMgr restricted.Manager

	// onHeartbeat is a callback for heartbeat status.
	onHeartbeat func(error)

	// utmpPath is the path to the user accounting database.
	utmpPath string

	// wtmpPath is the path to the user accounting log.
	wtmpPath string

	// allowTCPForwarding indicates whether the ssh server is allowed to offer
	// TCP port forwarding.
	allowTCPForwarding bool

	// x11 is the X11 forwarding configuration for the server
	x11 *x11.ServerConfig

	// lockWatcher is the server's lock watcher.
	lockWatcher *services.LockWatcher

	// connectedProxyGetter gets the proxies teleport is connected to.
	connectedProxyGetter *reversetunnel.ConnectedProxyGetter

	// nodeWatcher is the server's node watcher.
	nodeWatcher *services.NodeWatcher

	// createHostUser configures whether a host should allow host user
	// creation
	createHostUser bool

	storage *local.PresenceService

	// users is used to start the automatic user deletion loop
	users srv.HostUsers
	// awsMatchers are used to match EC2 instances
	awsMatchers []services.AWSMatcher

	// tracerProvider is used to create tracers capable
	// of starting spans.
	tracerProvider oteltrace.TracerProvider
}

// GetClock returns server clock implementation
func (s *Server) GetClock() clockwork.Clock {
	return s.clock
}

// GetDataDir returns server data dir
func (s *Server) GetDataDir() string {
	return s.dataDir
}

func (s *Server) GetNamespace() string {
	return s.namespace
}

func (s *Server) GetAccessPoint() srv.AccessPoint {
	return s.authService
}

func (s *Server) GetSessionServer() rsession.Service {
	if s.isAuditedAtProxy() {
		return rsession.NewDiscardSessionServer()
	}
	return s.sessionServer
}

// GetUtmpPath returns the optional override of the utmp and wtmp path.
func (s *Server) GetUtmpPath() (string, string) {
	return s.utmpPath, s.wtmpPath
}

// GetPAM returns the PAM configuration for this server.
func (s *Server) GetPAM() (*pam.Config, error) {
	return s.pamConfig, nil
}

// UseTunnel used to determine if this node has connected to this cluster
// using reverse tunnel.
func (s *Server) UseTunnel() bool {
	return s.useTunnel
}

// GetBPF returns the BPF service used by enhanced session recording.
func (s *Server) GetBPF() bpf.BPF {
	return s.ebpf
}

// GetRestrictedSessionManager returns the manager for restricting user activity.
func (s *Server) GetRestrictedSessionManager() restricted.Manager {
	return s.restrictedMgr
}

// GetLockWatcher gets the server's lock watcher.
func (s *Server) GetLockWatcher() *services.LockWatcher {
	return s.lockWatcher
}

// GetCreateHostUser determines whether users should be created on the
// host automatically
func (s *Server) GetCreateHostUser() bool {
	return s.createHostUser
}

// GetHostUsers returns the HostUsers instance being used to manage
// host user provisioning
func (s *Server) GetHostUsers() srv.HostUsers {
	return s.users
}

// isAuditedAtProxy returns true if sessions are being recorded at the proxy
// and this is a Teleport node.
func (s *Server) isAuditedAtProxy() bool {
	// always be safe, better to double record than not record at all
	recConfig, err := s.GetAccessPoint().GetSessionRecordingConfig(s.ctx)
	if err != nil {
		return false
	}

	isRecordAtProxy := services.IsRecordAtProxy(recConfig.GetMode())
	isTeleportNode := s.Component() == teleport.ComponentNode

	if isRecordAtProxy && isTeleportNode {
		return true
	}
	return false
}

// ServerOption is a functional option passed to the server
type ServerOption func(s *Server) error

func (s *Server) close() {
	s.Lock()
	defer s.Unlock()

	s.cancel()
	s.reg.Close()
	if s.heartbeat != nil {
		if err := s.heartbeat.Close(); err != nil {
			s.Warningf("Failed to close heartbeat: %v", err)
		}
		s.heartbeat = nil
	}
	if s.dynamicLabels != nil {
		s.dynamicLabels.Close()
	}

	if s.users != nil {
		s.users.Shutdown()
		s.users = nil
	}
}

// Close closes listening socket and stops accepting connections
func (s *Server) Close() error {
	s.close()
	return s.srv.Close()
}

// Shutdown performs graceful shutdown
func (s *Server) Shutdown(ctx context.Context) error {
	// wait until connections drain off
	err := s.srv.Shutdown(ctx)
	s.close()
	return err
}

// Start starts server
func (s *Server) Start() error {
	// Only call srv.Start() which listens on a socket if the server did not
	// request connections to it arrive over a reverse tunnel.
	if !s.useTunnel {
		if err := s.srv.Start(); err != nil {
			return trace.Wrap(err)
		}
	}
	// Heartbeat should start only after s.srv.Start.
	// If the server is configured to listen on port 0 (such as in tests),
	// it'll only populate its actual listening address during s.srv.Start.
	// Heartbeat uses this address to announce. Avoid announcing an empty
	// address on first heartbeat.
	s.startPeriodicOperations()
	return nil
}

// Serve servers service on started listener
func (s *Server) Serve(l net.Listener) error {
	s.startPeriodicOperations()
	return trace.Wrap(s.srv.Serve(l))
}

func (s *Server) startPeriodicOperations() {
	s.Lock()
	defer s.Unlock()

	// If the server has dynamic labels defined, start a loop that will
	// asynchronously keep them updated.
	if s.dynamicLabels != nil {
		go s.dynamicLabels.Start()
	}
	// If the server allows host user provisioning, this will start an
	// automatic cleanup process for any temporary leftover users.
	if s.users != nil {
		go s.users.UserCleanup()
	}
	if s.cloudLabels != nil {
		s.cloudLabels.Start(s.Context())
	}
	if s.heartbeat != nil {
		go s.heartbeat.Run()
	}
}

// Wait waits until server stops
func (s *Server) Wait() {
	s.srv.Wait(context.TODO())
}

// HandleConnection is called after a connection has been accepted and starts
// to perform the SSH handshake immediately.
func (s *Server) HandleConnection(conn net.Conn) {
	s.srv.HandleConnection(conn)
}

// RotationGetter returns rotation state
type RotationGetter func(role types.SystemRole) (*types.Rotation, error)

// SetUtmpPath is a functional server option to override the user accounting database and log path.
func SetUtmpPath(utmpPath, wtmpPath string) ServerOption {
	return func(s *Server) error {
		s.utmpPath = utmpPath
		s.wtmpPath = wtmpPath
		return nil
	}
}

// SetClock is a functional server option to override the internal
// clock
func SetClock(clock clockwork.Clock) ServerOption {
	return func(s *Server) error {
		s.clock = clock
		return nil
	}
}

// SetRotationGetter sets rotation state getter
func SetRotationGetter(getter RotationGetter) ServerOption {
	return func(s *Server) error {
		s.getRotation = getter
		return nil
	}
}

// SetShell sets default shell that will be executed for interactive
// sessions
func SetShell(shell string) ServerOption {
	return func(s *Server) error {
		s.shell = shell
		return nil
	}
}

// SetSessionServer represents realtime session registry server
func SetSessionServer(sessionServer rsession.Service) ServerOption {
	return func(s *Server) error {
		s.sessionServer = sessionServer
		return nil
	}
}

// SetProxyMode starts this server in SSH proxying mode
func SetProxyMode(peerAddr string, tsrv reversetunnel.Tunnel, ap auth.ReadProxyAccessPoint) ServerOption {
	return func(s *Server) error {
		// always set proxy mode to true,
		// because in some tests reverse tunnel is disabled,
		// but proxy is still used without it.
		s.proxyMode = true
		s.proxyTun = tsrv
		s.proxyAccessPoint = ap
		s.peerAddr = peerAddr
		return nil
	}
}

// SetLabels sets dynamic and static labels that server will report to the
// auth servers.
func SetLabels(staticLabels map[string]string, cmdLabels services.CommandLabels, cloudLabels labels.Importer) ServerOption {
	return func(s *Server) error {
		var err error

		// clone and validate labels and cmdLabels.  in theory,
		// only cmdLabels should experience concurrent writes,
		// but this operation is only run once on startup
		// so a little defensive cloning is harmless.
		labelsClone := make(map[string]string, len(staticLabels))
		for name, label := range staticLabels {
			if !types.IsValidLabelKey(name) {
				return trace.BadParameter("invalid label key: %q", name)
			}
			labelsClone[name] = label
		}
		s.labels = labelsClone

		// Create dynamic labels.
		s.dynamicLabels, err = labels.NewDynamic(s.ctx, &labels.DynamicConfig{
			Labels: cmdLabels,
		})
		if err != nil {
			return trace.Wrap(err)
		}
		s.cloudLabels = cloudLabels
		return nil
	}
}

// SetLimiter sets rate and connection limiter for this server
func SetLimiter(limiter *limiter.Limiter) ServerOption {
	return func(s *Server) error {
		s.limiter = limiter
		return nil
	}
}

// SetEmitter assigns an audit event emitter for this server
func SetEmitter(emitter events.StreamEmitter) ServerOption {
	return func(s *Server) error {
		s.StreamEmitter = emitter
		return nil
	}
}

// SetUUID sets server unique ID
func SetUUID(uuid string) ServerOption {
	return func(s *Server) error {
		s.uuid = uuid
		return nil
	}
}

func SetNamespace(namespace string) ServerOption {
	return func(s *Server) error {
		s.namespace = namespace
		return nil
	}
}

// SetPermitUserEnvironment allows you to set the value of permitUserEnvironment.
func SetPermitUserEnvironment(permitUserEnvironment bool) ServerOption {
	return func(s *Server) error {
		s.permitUserEnvironment = permitUserEnvironment
		return nil
	}
}

func SetCiphers(ciphers []string) ServerOption {
	return func(s *Server) error {
		s.ciphers = ciphers
		return nil
	}
}

func SetKEXAlgorithms(kexAlgorithms []string) ServerOption {
	return func(s *Server) error {
		s.kexAlgorithms = kexAlgorithms
		return nil
	}
}

func SetMACAlgorithms(macAlgorithms []string) ServerOption {
	return func(s *Server) error {
		s.macAlgorithms = macAlgorithms
		return nil
	}
}

func SetPAMConfig(pamConfig *pam.Config) ServerOption {
	return func(s *Server) error {
		s.pamConfig = pamConfig
		return nil
	}
}

func SetUseTunnel(useTunnel bool) ServerOption {
	return func(s *Server) error {
		s.useTunnel = useTunnel
		return nil
	}
}

func SetFIPS(fips bool) ServerOption {
	return func(s *Server) error {
		s.fips = fips
		return nil
	}
}

func SetBPF(ebpf bpf.BPF) ServerOption {
	return func(s *Server) error {
		s.ebpf = ebpf
		return nil
	}
}

func SetRestrictedSessionManager(m restricted.Manager) ServerOption {
	return func(s *Server) error {
		s.restrictedMgr = m
		return nil
	}
}

func SetOnHeartbeat(fn func(error)) ServerOption {
	return func(s *Server) error {
		s.onHeartbeat = fn
		return nil
	}
}

// SetCreateHostUser configures host user creation on a server
func SetCreateHostUser(createUser bool) ServerOption {
	return func(s *Server) error {
		s.createHostUser = createUser && runtime.GOOS == constants.LinuxOS
		return nil
	}
}

// SetStoragePresenceService configures host user creation on a server
func SetStoragePresenceService(service *local.PresenceService) ServerOption {
	return func(s *Server) error {
		s.storage = service
		return nil
	}
}

// SetAllowTCPForwarding sets the TCP port forwarding mode that this server is
// allowed to offer. The default value is SSHPortForwardingModeAll, i.e. port
// forwarding is allowed.
func SetAllowTCPForwarding(allow bool) ServerOption {
	return func(s *Server) error {
		s.allowTCPForwarding = allow
		return nil
	}
}

// SetLockWatcher sets the server's lock watcher.
func SetLockWatcher(lockWatcher *services.LockWatcher) ServerOption {
	return func(s *Server) error {
		s.lockWatcher = lockWatcher
		return nil
	}
}

// SetNodeWatcher sets the server's node watcher.
func SetNodeWatcher(nodeWatcher *services.NodeWatcher) ServerOption {
	return func(s *Server) error {
		s.nodeWatcher = nodeWatcher
		return nil
	}
}

// SetX11ForwardingConfig sets the server's X11 forwarding configuration
func SetX11ForwardingConfig(xc *x11.ServerConfig) ServerOption {
	return func(s *Server) error {
		s.x11 = xc
		return nil
	}
}

// SetConnectedProxyGetter sets the ConnectedProxyGetter.
func SetConnectedProxyGetter(getter *reversetunnel.ConnectedProxyGetter) ServerOption {
	return func(s *Server) error {
		s.connectedProxyGetter = getter
		return nil
	}
}

// SetInventoryControlHandle sets the server's downstream inventory control
// handle.
func SetInventoryControlHandle(handle inventory.DownstreamHandle) ServerOption {
	return func(s *Server) error {
		s.inventoryHandle = handle
		return nil
	}
}

// SetAWSMatchers sets the matchers used for matching EC2 instances
func SetAWSMatchers(matchers []services.AWSMatcher) ServerOption {
	return func(s *Server) error {
		s.awsMatchers = matchers
		return nil
	}
}

// SetTracerProvider sets the tracer provider.
func SetTracerProvider(provider oteltrace.TracerProvider) ServerOption {
	return func(s *Server) error {
		s.tracerProvider = provider
		return nil
	}
}

// New returns an unstarted server
func New(addr utils.NetAddr,
	hostname string,
	signers []ssh.Signer,
	authService srv.AccessPoint,
	dataDir string,
	advertiseAddr string,
	proxyPublicAddr utils.NetAddr,
	auth auth.ClientI,
	options ...ServerOption,
) (*Server, error) {
	err := utils.RegisterPrometheusCollectors(userSessionLimitHitCount)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// read the host UUID:
	uuid, err := utils.ReadOrMakeHostUUID(dataDir)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	ctx, cancel := context.WithCancel(context.TODO())
	s := &Server{
		addr:               addr,
		authService:        authService,
		hostname:           hostname,
		proxyPublicAddr:    proxyPublicAddr,
		uuid:               uuid,
		cancel:             cancel,
		ctx:                ctx,
		clock:              clockwork.NewRealClock(),
		dataDir:            dataDir,
		allowTCPForwarding: true,
	}
	s.limiter, err = limiter.NewLimiter(limiter.Config{})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if advertiseAddr != "" {
		s.advertiseAddr, err = utils.ParseAddr(advertiseAddr)
		if err != nil {
			return nil, trace.Wrap(err)
		}
	}

	for _, o := range options {
		if err := o(s); err != nil {
			return nil, trace.Wrap(err)
		}
	}

	// TODO(klizhentas): replace function arguments with struct
	if s.StreamEmitter == nil {
		return nil, trace.BadParameter("setup valid Emitter parameter using SetEmitter")
	}

	if s.namespace == "" {
		return nil, trace.BadParameter("setup valid namespace parameter using SetNamespace")
	}

	if s.lockWatcher == nil {
		return nil, trace.BadParameter("setup valid LockWatcher parameter using SetLockWatcher")
	}

	if s.connectedProxyGetter == nil {
		s.connectedProxyGetter = reversetunnel.NewConnectedProxyGetter()
	}

	if s.tracerProvider == nil {
		s.tracerProvider = tracing.DefaultProvider()
	}

	var component string
	if s.proxyMode {
		component = teleport.ComponentProxy
	} else {
		component = teleport.ComponentNode
	}

	s.Entry = logrus.WithFields(logrus.Fields{
		trace.Component:       component,
		trace.ComponentFields: logrus.Fields{},
	})

	if s.createHostUser {
		users := srv.NewHostUsers(ctx, s.storage, s.ID())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		s.users = users
	}

	s.reg, err = srv.NewSessionRegistry(srv.SessionRegistryConfig{
		Srv:                   s,
		SessionTrackerService: auth,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// add in common auth handlers
	authHandlerConfig := srv.AuthHandlerConfig{
		Server:      s,
		Component:   component,
		AccessPoint: s.authService,
		FIPS:        s.fips,
		Emitter:     s.StreamEmitter,
		Clock:       s.clock,
	}

	s.authHandlers, err = srv.NewAuthHandlers(&authHandlerConfig)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// common term handlers
	s.termHandlers = &srv.TermHandlers{
		SessionRegistry: s.reg,
	}

	server, err := sshutils.NewServer(
		component,
		addr, s, signers,
		sshutils.AuthMethods{PublicKey: s.authHandlers.UserKeyAuth},
		sshutils.SetLimiter(s.limiter),
		sshutils.SetRequestHandler(s),
		sshutils.SetNewConnHandler(s),
		sshutils.SetCiphers(s.ciphers),
		sshutils.SetKEXAlgorithms(s.kexAlgorithms),
		sshutils.SetMACAlgorithms(s.macAlgorithms),
		sshutils.SetFIPS(s.fips),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	s.srv = server

	var heartbeatMode srv.HeartbeatMode
	if s.proxyMode {
		heartbeatMode = srv.HeartbeatModeProxy
	} else {
		heartbeatMode = srv.HeartbeatModeNode
	}

	var heartbeat srv.HeartbeatI
	if heartbeatMode == srv.HeartbeatModeNode && s.inventoryHandle != nil {
		log.Info("debug -> starting control-stream based heartbeat.")
		heartbeat, err = srv.NewSSHServerHeartbeat(srv.SSHServerHeartbeatConfig{
			InventoryHandle: s.inventoryHandle,
			GetServer:       s.getServerInfo,
			Announcer:       s.authService,
			OnHeartbeat:     s.onHeartbeat,
		})
	} else {
		log.Info("debug -> starting legacy heartbeat.")
		heartbeat, err = srv.NewHeartbeat(srv.HeartbeatConfig{
			Mode:            heartbeatMode,
			Context:         ctx,
			Component:       component,
			Announcer:       s.authService,
			GetServerInfo:   s.getServerResource,
			KeepAlivePeriod: apidefaults.ServerKeepAliveTTL(),
			AnnouncePeriod:  apidefaults.ServerAnnounceTTL/2 + utils.RandomDuration(apidefaults.ServerAnnounceTTL/10),
			ServerTTL:       apidefaults.ServerAnnounceTTL,
			CheckPeriod:     defaults.HeartbeatCheckPeriod,
			Clock:           s.clock,
			OnHeartbeat:     s.onHeartbeat,
		})
	}
	if err != nil {
		s.srv.Close()
		return nil, trace.Wrap(err)
	}

	s.heartbeat = heartbeat

	return s, nil
}

func (s *Server) getNamespace() string {
	return types.ProcessNamespace(s.namespace)
}

func (s *Server) tunnelWithAccessChecker(ctx *srv.ServerContext) reversetunnel.Tunnel {
	return reversetunnel.NewTunnelWithRoles(s.proxyTun, ctx.Identity.AccessChecker, s.proxyAccessPoint)
}

// Context returns server shutdown context
func (s *Server) Context() context.Context {
	return s.ctx
}

func (s *Server) Component() string {
	if s.proxyMode {
		return teleport.ComponentProxy
	}
	return teleport.ComponentNode
}

// Addr returns server address
func (s *Server) Addr() string {
	return s.srv.Addr()
}

// ID returns server ID
func (s *Server) ID() string {
	return s.uuid
}

// HostUUID is the ID of the server. This value is the same as ID, it is
// different from the forwarding server.
func (s *Server) HostUUID() string {
	return s.uuid
}

// PermitUserEnvironment returns if ~/.tsh/environment will be read before a
// session is created by this server.
func (s *Server) PermitUserEnvironment() bool {
	return s.permitUserEnvironment
}

func (s *Server) setAdvertiseAddr(addr *utils.NetAddr) {
	s.Lock()
	defer s.Unlock()
	s.advertiseAddr = addr
}

func (s *Server) getAdvertiseAddr() *utils.NetAddr {
	s.Lock()
	defer s.Unlock()
	return s.advertiseAddr
}

// AdvertiseAddr returns an address this server should be publicly accessible
// as, in "ip:host" form
func (s *Server) AdvertiseAddr() string {
	// set if we have explicit --advertise-ip option
	advertiseAddr := s.getAdvertiseAddr()
	listenAddr := s.Addr()
	if advertiseAddr == nil {
		return listenAddr
	}
	_, port, _ := net.SplitHostPort(listenAddr)
	ahost, aport, err := utils.ParseAdvertiseAddr(advertiseAddr.String())
	if err != nil {
		log.Warningf("Failed to parse advertise address %q, %v, using default value %q.", advertiseAddr, err, listenAddr)
		return listenAddr
	}
	if aport == "" {
		aport = port
	}
	return net.JoinHostPort(ahost, aport)
}

func (s *Server) getRole() types.SystemRole {
	if s.proxyMode {
		return types.RoleProxy
	}
	return types.RoleNode
}

// getStaticLabels gets the labels that the server should present as static,
// which includes EC2 labels if available.
func (s *Server) getStaticLabels() map[string]string {
	if s.cloudLabels == nil {
		return s.labels
	}
	labels := s.cloudLabels.Get()
	// Let static labels override ec2 labels if they conflict.
	for k, v := range s.labels {
		labels[k] = v
	}
	return labels
}

// getDynamicLabels returns all dynamic labels. If no dynamic labels are
// defined, return an empty set.
func (s *Server) getDynamicLabels() map[string]types.CommandLabelV2 {
	if s.dynamicLabels == nil {
		return make(map[string]types.CommandLabelV2)
	}
	return types.LabelsToV2(s.dynamicLabels.Get())
}

// GetInfo returns a services.Server that represents this server.
func (s *Server) GetInfo() types.Server {
	return s.getBasicInfo()
}

func (s *Server) getBasicInfo() *types.ServerV2 {
	// Only set the address for non-tunnel nodes.
	var addr string
	if !s.useTunnel {
		addr = s.AdvertiseAddr()
	}

	return &types.ServerV2{
		Kind:    types.KindNode,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      s.ID(),
			Namespace: s.getNamespace(),
			Labels:    s.getStaticLabels(),
		},
		Spec: types.ServerSpecV2{
			CmdLabels: s.getDynamicLabels(),
			Addr:      addr,
			Hostname:  s.hostname,
			UseTunnel: s.useTunnel,
			Version:   teleport.Version,
			ProxyIDs:  s.connectedProxyGetter.GetProxyIDs(),
		},
	}
}

func (s *Server) getServerInfo() *types.ServerV2 {
	server := s.getBasicInfo()
	if s.getRotation != nil {
		rotation, err := s.getRotation(s.getRole())
		if err != nil {
			if !trace.IsNotFound(err) {
				log.Warningf("Failed to get rotation state: %v", err)
			}
		} else {
			server.SetRotation(*rotation)
		}
	}

	server.SetExpiry(s.clock.Now().UTC().Add(apidefaults.ServerAnnounceTTL))
	server.SetPublicAddr(s.proxyPublicAddr.String())
	server.SetPeerAddr(s.peerAddr)
	return server
}

func (s *Server) getServerResource() (types.Resource, error) {
	return s.getServerInfo(), nil
}

// serveAgent will build the a sock path for this user and serve an SSH agent on unix socket.
func (s *Server) serveAgent(ctx *srv.ServerContext) error {
	// gather information about user and process. this will be used to set the
	// socket path and permissions
	systemUser, err := user.Lookup(ctx.Identity.Login)
	if err != nil {
		return trace.ConvertSystemError(err)
	}

	pid := os.Getpid()

	socketDir := "teleport"
	socketName := fmt.Sprintf("teleport-%v.socket", pid)

	// start an agent server on a unix socket.  each incoming connection
	// will result in a separate agent request.
	agentServer := teleagent.NewServer(ctx.Parent().StartAgentChannel)
	err = agentServer.ListenUnixSocket(socketDir, socketName, systemUser)
	if err != nil {
		return trace.Wrap(err)
	}

	ctx.Parent().SetEnv(teleport.SSHAuthSock, agentServer.Path)
	ctx.Parent().SetEnv(teleport.SSHAgentPID, fmt.Sprintf("%v", pid))
	ctx.Parent().AddCloser(agentServer)
	ctx.Debugf("Starting agent server for Teleport user %v and socket %v.", ctx.Identity.TeleportUser, agentServer.Path)
	go func() {
		if err := agentServer.Serve(); err != nil {
			ctx.Errorf("agent server for user %q stopped: %v", ctx.Identity.TeleportUser, err)
		}
	}()

	return nil
}

// HandleRequest processes global out-of-band requests. Global out-of-band
// requests are processed in order (this way the originator knows which
// request we are responding to). If Teleport does not support the request
// type or an error occurs while processing that request Teleport will reply
// req.Reply(false, nil).
//
// For more details: https://tools.ietf.org/html/rfc4254.html#page-4
func (s *Server) HandleRequest(ctx context.Context, r *ssh.Request) {
	switch r.Type {
	case teleport.KeepAliveReqType:
		s.handleKeepAlive(r)
	case teleport.RecordingProxyReqType:
		s.handleRecordingProxy(r)
	case teleport.VersionRequest:
		s.handleVersionRequest(r)
	case teleport.TerminalSizeRequest:
		s.termHandlers.HandleTerminalSize(r)
	default:
		if r.WantReply {
			if err := r.Reply(false, nil); err != nil {
				log.Warnf("Failed to reply to %q request: %v", r.Type, err)
			}
		}
		log.Debugf("Discarding %q global request: %+v", r.Type, r)
	}
}

// HandleNewConn is called by sshutils.Server once for each new incoming connection,
// prior to handling any channels or requests.  Currently this callback's only
// function is to apply session control restrictions.
func (s *Server) HandleNewConn(ctx context.Context, ccx *sshutils.ConnectionContext) (context.Context, error) {
	identityContext, err := s.authHandlers.CreateIdentityContext(ccx.ServerConn)
	if err != nil {
		return ctx, trace.Wrap(err)
	}
	authPref, err := s.GetAccessPoint().GetAuthPreference(ctx)
	if err != nil {
		return ctx, trace.Wrap(err)
	}
	lockingMode := identityContext.AccessChecker.LockingMode(authPref.GetLockingMode())

	event := &apievents.SessionReject{
		Metadata: apievents.Metadata{
			Type: events.SessionRejectedEvent,
			Code: events.SessionRejectedCode,
		},
		UserMetadata: identityContext.GetUserMetadata(),
		ConnectionMetadata: apievents.ConnectionMetadata{
			Protocol:   events.EventProtocolSSH,
			LocalAddr:  ccx.ServerConn.LocalAddr().String(),
			RemoteAddr: ccx.ServerConn.RemoteAddr().String(),
		},
		ServerMetadata: apievents.ServerMetadata{
			ServerID:        s.uuid,
			ServerNamespace: s.GetNamespace(),
		},
	}

	lockTargets, err := srv.ComputeLockTargets(s, identityContext)
	if err != nil {
		return ctx, trace.Wrap(err)
	}
	if lockErr := s.lockWatcher.CheckLockInForce(lockingMode, lockTargets...); lockErr != nil {
		event.Reason = lockErr.Error()
		if err := s.EmitAuditEvent(s.ctx, event); err != nil {
			log.WithError(err).Warn("Failed to emit session reject event.")
		}
		return ctx, trace.Wrap(lockErr)
	}

	// Don't apply the following checks in non-node contexts.
	if s.Component() != teleport.ComponentNode {
		return ctx, nil
	}

	maxConnections := identityContext.AccessChecker.MaxConnections()
	if maxConnections == 0 {
		// concurrent session control is not active, nothing
		// else needs to be done here.
		return ctx, nil
	}

	netConfig, err := s.GetAccessPoint().GetClusterNetworkingConfig(ctx)
	if err != nil {
		return ctx, trace.Wrap(err)
	}

	semLock, err := services.AcquireSemaphoreLock(ctx, services.SemaphoreLockConfig{
		Service: s.authService,
		Expiry:  netConfig.GetSessionControlTimeout(),
		Params: types.AcquireSemaphoreRequest{
			SemaphoreKind: types.SemaphoreKindConnection,
			SemaphoreName: identityContext.TeleportUser,
			MaxLeases:     maxConnections,
			Holder:        s.uuid,
		},
	})
	if err != nil {
		if strings.Contains(err.Error(), teleport.MaxLeases) {
			// user has exceeded their max concurrent ssh connections.
			userSessionLimitHitCount.Inc()
			event.Reason = events.SessionRejectedEvent
			event.Maximum = maxConnections
			if err := s.EmitAuditEvent(s.ctx, event); err != nil {
				log.WithError(err).Warn("Failed to emit session reject event.")
			}
			err = trace.AccessDenied("too many concurrent ssh connections for user %q (max=%d)",
				identityContext.TeleportUser,
				maxConnections,
			)
		}
		return ctx, trace.Wrap(err)
	}

	// ensure that losing the lock closes the connection context.  Under normal
	// conditions, cancellation propagates from the connection context to the
	// lock, but if we lose the lock due to some error (e.g. poor connectivity
	// to auth server) then cancellation propagates in the other direction.
	go func() {
		// TODO(fspmarshall): If lock was lost due to error, find a way to propagate
		// an error message to user.
		<-semLock.Done()
		ccx.Close()
	}()
	return ctx, nil
}

// HandleNewChan is called when new channel is opened
func (s *Server) HandleNewChan(ctx context.Context, ccx *sshutils.ConnectionContext, nch ssh.NewChannel) {
	identityContext, err := s.authHandlers.CreateIdentityContext(ccx.ServerConn)
	if err != nil {
		rejectChannel(nch, ssh.Prohibited, fmt.Sprintf("Unable to create identity from connection: %v", err))
		return
	}

	channelType := nch.ChannelType()
	if s.proxyMode {
		switch channelType {
		// Channels of type "tracing-request" are sent to determine if ssh tracing envelopes
		// are supported. Accepting the channel indicates to clients that they may wrap their
		// ssh payload with tracing context.
		case tracessh.TracingChannel:
			ch, _, err := nch.Accept()
			if err != nil {
				if err := nch.Reject(ssh.ConnectionFailed, err.Error()); err != nil {
					log.Warnf("Unable to reject %q channel: %v", nch.ChannelType(), err)
				}
				return
			}
			if err := ch.Close(); err != nil {
				log.Warnf("Unable to close %q channel: %v", nch.ChannelType(), err)
			}
			return
		// Channels of type "direct-tcpip", for proxies, it's equivalent
		// of teleport proxy: subsystem
		case teleport.ChanDirectTCPIP:
			req, err := sshutils.ParseDirectTCPIPReq(nch.ExtraData())
			if err != nil {
				log.Errorf("Failed to parse request data: %v, err: %v.", string(nch.ExtraData()), err)
				rejectChannel(nch, ssh.UnknownChannelType, "failed to parse direct-tcpip request")
				return
			}
			ch, _, err := nch.Accept()
			if err != nil {
				log.Warnf("Unable to accept channel: %v.", err)
				rejectChannel(nch, ssh.ConnectionFailed, fmt.Sprintf("unable to accept channel: %v", err))
				return
			}
			go s.handleProxyJump(ctx, ccx, identityContext, ch, *req)
			return
		// Channels of type "session" handle requests that are involved in running
		// commands on a server. In the case of proxy mode subsystem and agent
		// forwarding requests occur over the "session" channel.
		case teleport.ChanSession:
			ch, requests, err := nch.Accept()
			if err != nil {
				log.Warnf("Unable to accept channel: %v.", err)
				rejectChannel(nch, ssh.ConnectionFailed, fmt.Sprintf("unable to accept channel: %v", err))
				return
			}
			go s.handleSessionRequests(ctx, ccx, identityContext, ch, requests)
			return
		default:
			rejectChannel(nch, ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
			return
		}
	}

	switch channelType {
	// Channels of type "tracing-request" are sent to determine if ssh tracing envelopes
	// are supported. Accepting the channel indicates to clients that they may wrap their
	// ssh payload with tracing context.
	case tracessh.TracingChannel:
		ch, _, err := nch.Accept()
		if err != nil {
			if err := nch.Reject(ssh.ConnectionFailed, err.Error()); err != nil {
				log.Warnf("Unable to reject %q channel: %v", nch.ChannelType(), err)
			}
			return
		}

		if err := ch.Close(); err != nil {
			log.Warnf("Unable to close %q channel: %v", nch.ChannelType(), err)
		}
		return
	// Channels of type "session" handle requests that are involved in running
	// commands on a server, subsystem requests, and agent forwarding.
	case teleport.ChanSession:
		var decr func()
		if max := identityContext.AccessChecker.MaxSessions(); max != 0 {
			d, ok := ccx.IncrSessions(max)
			if !ok {
				// user has exceeded their max concurrent ssh sessions.
				if err := s.EmitAuditEvent(s.ctx, &apievents.SessionReject{
					Metadata: apievents.Metadata{
						Type: events.SessionRejectedEvent,
						Code: events.SessionRejectedCode,
					},
					UserMetadata: identityContext.GetUserMetadata(),
					ConnectionMetadata: apievents.ConnectionMetadata{
						Protocol:   events.EventProtocolSSH,
						LocalAddr:  ccx.ServerConn.LocalAddr().String(),
						RemoteAddr: ccx.ServerConn.RemoteAddr().String(),
					},
					ServerMetadata: apievents.ServerMetadata{
						ServerID:        s.uuid,
						ServerNamespace: s.GetNamespace(),
					},
					Reason:  events.SessionRejectedReasonMaxSessions,
					Maximum: max,
				}); err != nil {
					log.WithError(err).Warn("Failed to emit session reject event.")
				}
				rejectChannel(nch, ssh.Prohibited, fmt.Sprintf("too many session channels for user %q (max=%d)", identityContext.TeleportUser, max))
				return
			}
			decr = d
		}
		ch, requests, err := nch.Accept()
		if err != nil {
			log.Warnf("Unable to accept channel: %v.", err)
			rejectChannel(nch, ssh.ConnectionFailed, fmt.Sprintf("unable to accept channel: %v", err))
			if decr != nil {
				decr()
			}
			return
		}
		go func() {
			s.handleSessionRequests(ctx, ccx, identityContext, ch, requests)
			if decr != nil {
				decr()
			}
		}()
	// Channels of type "direct-tcpip" handles request for port forwarding.
	case teleport.ChanDirectTCPIP:
		req, err := sshutils.ParseDirectTCPIPReq(nch.ExtraData())
		if err != nil {
			log.Errorf("Failed to parse request data: %v, err: %v.", string(nch.ExtraData()), err)
			rejectChannel(nch, ssh.UnknownChannelType, "failed to parse direct-tcpip request")
			return
		}
		ch, _, err := nch.Accept()
		if err != nil {
			log.Warnf("Unable to accept channel: %v.", err)
			rejectChannel(nch, ssh.ConnectionFailed, fmt.Sprintf("unable to accept channel: %v", err))
			return
		}
		go s.handleDirectTCPIPRequest(ctx, ccx, identityContext, ch, req)
	default:
		rejectChannel(nch, ssh.UnknownChannelType, fmt.Sprintf("unknown channel type: %v", channelType))
	}
}

// canPortForward determines if port forwarding is allowed for the current
// user/role/node combo. Returns nil if port forwarding is allowed, non-nil
// if denied.
func (s *Server) canPortForward(scx *srv.ServerContext, channel ssh.Channel) error {
	// Is the node configured to allow port forwarding?
	if !s.allowTCPForwarding {
		return trace.AccessDenied("node does not allow port forwarding")
	}

	// Check if the role allows port forwarding for this user.
	err := s.authHandlers.CheckPortForward(scx.DstAddr, scx)
	if err != nil {
		return err
	}

	return nil
}

// stderrWriter wraps an ssh.Channel in an implementation of io.StringWriter
// that sends anything written back the client over its stderr stream
type stderrWriter struct {
	channel ssh.Channel
}

func (w *stderrWriter) WriteString(s string) (int, error) {
	writeStderr(w.channel, s)
	return len(s), nil
}

// handleDirectTCPIPRequest handles port forwarding requests.
func (s *Server) handleDirectTCPIPRequest(ctx context.Context, ccx *sshutils.ConnectionContext, identityContext srv.IdentityContext, channel ssh.Channel, req *sshutils.DirectTCPIPReq) {
	// Create context for this channel. This context will be closed when
	// forwarding is complete.
	ctx, scx, err := srv.NewServerContext(ctx, ccx, s, identityContext)
	if err != nil {
		log.WithError(err).Error("Unable to create connection context.")
		writeStderr(channel, "Unable to create connection context.")
		if err := channel.Close(); err != nil {
			log.WithError(err).Warn("Failed to close channel.")
		}
		return
	}
	scx.IsTestStub = s.isTestStub
	scx.AddCloser(channel)
	scx.ChannelType = teleport.ChanDirectTCPIP
	scx.SrcAddr = net.JoinHostPort(req.Orig, strconv.Itoa(int(req.OrigPort)))
	scx.DstAddr = net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))
	defer scx.Close()

	channel = scx.TrackActivity(channel)

	// Bail out now if TCP port forwarding is not allowed for this node/user/role
	// combo
	if err = s.canPortForward(scx, channel); err != nil {
		writeStderr(channel, err.Error())
		return
	}

	scx.Debugf("Opening direct-tcpip channel from %v to %v.", scx.SrcAddr, scx.DstAddr)
	defer scx.Debugf("Closing direct-tcpip channel from %v to %v.", scx.SrcAddr, scx.DstAddr)

	// Create command to re-exec Teleport which will perform a net.Dial. The
	// reason it's not done directly is because the PAM stack needs to be called
	// from another process.
	cmd, err := srv.ConfigureCommand(scx)
	if err != nil {
		writeStderr(channel, err.Error())
		return
	}
	// Propagate stderr from the spawned Teleport process to log any errors.
	cmd.Stderr = os.Stderr

	// Create a pipe for std{in,out} that will be used to transfer data between
	// parent and child.
	pr, err := cmd.StdoutPipe()
	if err != nil {
		log.Errorf("Failed to setup stdout pipe: %v", err)
		writeStderr(channel, err.Error())
		return
	}
	pw, err := cmd.StdinPipe()
	if err != nil {
		log.Errorf("Failed to setup stdin pipe: %v", err)
		writeStderr(channel, err.Error())
		return
	}

	// Start the child process that will be used to make the actual connection
	// to the target host.
	err = cmd.Start()
	if err != nil {
		writeStderr(channel, err.Error())
		return
	}

	// Start copy routines that copy from channel to stdin pipe and from stdout
	// pipe to channel.
	errorCh := make(chan error, 2)
	go func() {
		defer channel.Close()
		defer pw.Close()
		defer pr.Close()

		_, err := io.Copy(pw, channel)
		errorCh <- err
	}()
	go func() {
		defer channel.Close()
		defer pw.Close()
		defer pr.Close()

		_, err := io.Copy(channel, pr)
		errorCh <- err
	}()

	// Block until copy is complete and the child process is done executing.
Loop:
	for i := 0; i < 2; i++ {
		select {
		case err := <-errorCh:
			if err != nil && err != io.EOF {
				log.Warnf("Connection problem in \"direct-tcpip\" channel: %v %T.", trace.DebugReport(err), err)
			}
		case <-ctx.Done():
			break Loop
		case <-s.ctx.Done():
			break Loop
		}
	}
	err = cmd.Wait()
	if err != nil {
		writeStderr(channel, err.Error())
		return
	}

	// Emit a port forwarding event.
	if err := s.EmitAuditEvent(s.ctx, &apievents.PortForward{
		Metadata: apievents.Metadata{
			Type: events.PortForwardEvent,
			Code: events.PortForwardCode,
		},
		UserMetadata: scx.Identity.GetUserMetadata(),
		ConnectionMetadata: apievents.ConnectionMetadata{
			LocalAddr:  scx.ServerConn.LocalAddr().String(),
			RemoteAddr: scx.ServerConn.RemoteAddr().String(),
		},
		Addr: scx.DstAddr,
		Status: apievents.Status{
			Success: true,
		},
	}); err != nil {
		log.WithError(err).Warn("Failed to emit port forward event.")
	}
}

// handleSessionRequests handles out of band session requests once the session
// channel has been created this function's loop handles all the "exec",
// "subsystem" and "shell" requests.
func (s *Server) handleSessionRequests(ctx context.Context, ccx *sshutils.ConnectionContext, identityContext srv.IdentityContext, ch ssh.Channel, in <-chan *ssh.Request) {
	netConfig, err := s.GetAccessPoint().GetClusterNetworkingConfig(ctx)
	if err != nil {
		log.Errorf("Unable to fetch cluster networking config: %v.", err)
		writeStderr(ch, "Unable to fetch cluster networking configuration.")
		return
	}

	// Create context for this channel. This context will be closed when the
	// session request is complete.
	ctx, scx, err := srv.NewServerContext(ctx, ccx, s, identityContext, func(cfg *srv.MonitorConfig) {
		cfg.IdleTimeoutMessage = netConfig.GetClientIdleTimeoutMessage()
		cfg.MessageWriter = &stderrWriter{channel: ch}
	})
	if err != nil {
		log.WithError(err).Error("Unable to create connection context.")
		writeStderr(ch, "Unable to create connection context.")
		if err := ch.Close(); err != nil {
			log.WithError(err).Warn("Failed to close channel.")
		}
		return
	}
	scx.IsTestStub = s.isTestStub
	scx.AddCloser(ch)
	scx.ChannelType = teleport.ChanSession
	defer scx.Close()

	ch = scx.TrackActivity(ch)

	// The keep-alive loop will keep pinging the remote server and after it has
	// missed a certain number of keep-alive requests it will cancel the
	// closeContext which signals the server to shutdown.
	go srv.StartKeepAliveLoop(srv.KeepAliveParams{
		Conns: []srv.RequestSender{
			scx.ServerConn,
		},
		Interval:     netConfig.GetKeepAliveInterval(),
		MaxCount:     netConfig.GetKeepAliveCountMax(),
		CloseContext: ctx,
		CloseCancel:  scx.CancelFunc(),
	})

	for {
		// update scx with the session ID:
		if !s.proxyMode {
			err := scx.CreateOrJoinSession(s.reg)
			if err != nil {
				errorMessage := fmt.Sprintf("unable to update context: %v", err)
				scx.Errorf("Unable to update context: %v.", errorMessage)

				// write the error to channel and close it
				writeStderr(ch, errorMessage)
				_, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{C: teleport.RemoteCommandFailure}))
				if err != nil {
					scx.Errorf("Failed to send exit status %v.", errorMessage)
				}
				return
			}
		}
		select {
		case creq := <-scx.SubsystemResultCh:
			// this means that subsystem has finished executing and
			// want us to close session and the channel
			scx.Debugf("Close session request: %v.", creq.Err)
			return
		case req := <-in:
			if req == nil {
				// this will happen when the client closes/drops the connection
				scx.Debugf("Client %v disconnected.", scx.ServerConn.RemoteAddr())
				return
			}

			reqCtx := tracessh.ContextFromRequest(req)
			ctx, span := s.tracerProvider.Tracer("ssh").Start(
				oteltrace.ContextWithRemoteSpanContext(ctx, oteltrace.SpanContextFromContext(reqCtx)),
				fmt.Sprintf("ssh.Regular.SessionRequest/%s", req.Type),
				oteltrace.WithSpanKind(oteltrace.SpanKindServer),
				oteltrace.WithAttributes(
					semconv.RPCServiceKey.String("ssh.RegularServer"),
					semconv.RPCMethodKey.String("SessionRequest"),
					semconv.RPCSystemKey.String("ssh"),
				),
			)

			if err := s.dispatch(ctx, ch, req, scx); err != nil {
				s.replyError(ch, req, err)
				span.End()
				return
			}
			if req.WantReply {
				if err := req.Reply(true, nil); err != nil {
					log.Warnf("Failed to reply to %q request: %v", req.Type, err)
				}
			}
			span.End()
		case result := <-scx.ExecResultCh:
			scx.Debugf("Exec request (%q) complete: %v", result.Command, result.Code)

			// The exec process has finished and delivered the execution result, send
			// the result back to the client, and close the session and channel.
			_, err := ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{C: uint32(result.Code)}))
			if err != nil {
				scx.Infof("Failed to send exit status for %v: %v", result.Command, err)
			}

			return
		case <-ctx.Done():
			log.Debugf("Closing session due to cancellation.")
			return
		}
	}
}

// dispatch receives an SSH request for a subsystem and dispatches the request to the
// appropriate subsystem implementation
func (s *Server) dispatch(ctx context.Context, ch ssh.Channel, req *ssh.Request, serverContext *srv.ServerContext) error {
	serverContext.Debugf("Handling request %v, want reply %v.", req.Type, req.WantReply)

	// If this SSH server is configured to only proxy, we do not support anything
	// other than our own custom "subsystems" and environment manipulation.
	if s.proxyMode {
		switch req.Type {
		case tracessh.TracingRequest:
			return nil
		case sshutils.SubsystemRequest:
			return s.handleSubsystem(ctx, ch, req, serverContext)
		case sshutils.EnvRequest:
			// we currently ignore setting any environment variables via SSH for security purposes
			return s.handleEnv(ch, req, serverContext)
		case sshutils.AgentForwardRequest:
			// process agent forwarding, but we will only forward agent to proxy in
			// recording proxy mode.
			err := s.handleAgentForwardProxy(req, serverContext)
			if err != nil {
				log.Warn(err)
			}
			return nil
		case sshutils.PuTTYSimpleRequest:
			// PuTTY automatically requests a named 'simple@putty.projects.tartarus.org' channel any time it connects to a server
			// as a proxy to indicate that it's in "simple" node and won't be requesting any other channels.
			// As we don't support this request, we ignore it.
			// https://the.earth.li/~sgtatham/putty/0.76/htmldoc/AppendixG.html#sshnames-channel
			log.Debugf("%v: deliberately ignoring request for '%v' channel", s.Component(), sshutils.PuTTYSimpleRequest)
			return nil
		default:
			return trace.BadParameter(
				"(%v) proxy doesn't support request type '%v'", s.Component(), req.Type)
		}
	}

	// Certs with a join-only principal can only use a
	// subset of all the possible request types.
	if serverContext.JoinOnly {
		switch req.Type {
		case tracessh.TracingRequest:
			return nil
		case sshutils.PTYRequest:
			return s.termHandlers.HandlePTYReq(ctx, ch, req, serverContext)
		case sshutils.ShellRequest:
			return s.termHandlers.HandleShell(ctx, ch, req, serverContext)
		case sshutils.WindowChangeRequest:
			return s.termHandlers.HandleWinChange(ctx, ch, req, serverContext)
		case teleport.ForceTerminateRequest:
			return s.termHandlers.HandleForceTerminate(ch, req, serverContext)
		case sshutils.EnvRequest:
			// We ignore all SSH setenv requests for join-only principals.
			// SSH will send them anyway but it seems fine to silently drop them.
		case sshutils.SubsystemRequest:
			return s.handleSubsystem(ctx, ch, req, serverContext)
		case sshutils.AgentForwardRequest:
			// This happens when SSH client has agent forwarding enabled, in this case
			// client sends a special request, in return SSH server opens new channel
			// that uses SSH protocol for agent drafted here:
			// https://tools.ietf.org/html/draft-ietf-secsh-agent-02
			// the open ssh proto spec that we implement is here:
			// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent

			// to maintain interoperability with OpenSSH, agent forwarding requests
			// should never fail, all errors should be logged and we should continue
			// processing requests.
			err := s.handleAgentForwardNode(req, serverContext)
			if err != nil {
				log.Warn(err)
			}
			return nil
		default:
			return trace.AccessDenied("attempted %v request in join-only mode", req.Type)
		}
	}

	switch req.Type {
	case tracessh.TracingRequest:
		return nil
	case sshutils.ExecRequest:
		return s.termHandlers.HandleExec(ctx, ch, req, serverContext)
	case sshutils.PTYRequest:
		return s.termHandlers.HandlePTYReq(ctx, ch, req, serverContext)
	case sshutils.ShellRequest:
		return s.termHandlers.HandleShell(ctx, ch, req, serverContext)
	case sshutils.WindowChangeRequest:
		return s.termHandlers.HandleWinChange(ctx, ch, req, serverContext)
	case teleport.ForceTerminateRequest:
		return s.termHandlers.HandleForceTerminate(ch, req, serverContext)
	case sshutils.EnvRequest:
		return s.handleEnv(ch, req, serverContext)
	case sshutils.SubsystemRequest:
		// subsystems are SSH subsystems defined in http://tools.ietf.org/html/rfc4254 6.6
		// they are in essence SSH session extensions, allowing to implement new SSH commands
		return s.handleSubsystem(ctx, ch, req, serverContext)
	case sshutils.X11ForwardRequest:
		return s.handleX11Forward(ch, req, serverContext)
	case sshutils.AgentForwardRequest:
		// This happens when SSH client has agent forwarding enabled, in this case
		// client sends a special request, in return SSH server opens new channel
		// that uses SSH protocol for agent drafted here:
		// https://tools.ietf.org/html/draft-ietf-secsh-agent-02
		// the open ssh proto spec that we implement is here:
		// http://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.agent

		// to maintain interoperability with OpenSSH, agent forwarding requests
		// should never fail, all errors should be logged and we should continue
		// processing requests.
		err := s.handleAgentForwardNode(req, serverContext)
		if err != nil {
			log.Warn(err)
		}
		return nil
	default:
		return trace.BadParameter(
			"%v doesn't support request type '%v'", s.Component(), req.Type)
	}
}

// handleAgentForwardNode will create a unix socket and serve the agent running
// on the client on it.
func (s *Server) handleAgentForwardNode(req *ssh.Request, ctx *srv.ServerContext) error {
	// check if the user's RBAC role allows agent forwarding
	err := s.authHandlers.CheckAgentForward(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Enable agent forwarding for the broader connection-level
	// context.
	ctx.Parent().SetForwardAgent(true)

	// serve an agent on a unix socket on this node
	err = s.serveAgent(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// handleAgentForwardProxy will forward the clients agent to the proxy (when
// the proxy is running in recording mode). When running in normal mode, this
// request will do nothing. To maintain interoperability, agent forwarding
// requests should never fail, all errors should be logged and we should
// continue processing requests.
func (s *Server) handleAgentForwardProxy(req *ssh.Request, ctx *srv.ServerContext) error {
	// Forwarding an agent to the proxy is only supported when the proxy is in
	// recording mode.
	if services.IsRecordAtProxy(ctx.SessionRecordingConfig.GetMode()) == false {
		return trace.BadParameter("agent forwarding to proxy only supported in recording mode")
	}

	// Check if the user's RBAC role allows agent forwarding.
	err := s.authHandlers.CheckAgentForward(ctx)
	if err != nil {
		return trace.Wrap(err)
	}

	// Enable agent forwarding for the broader connection-level
	// context.
	ctx.Parent().SetForwardAgent(true)

	return nil
}

// handleX11Forward handles an X11 forwarding request from the client.
func (s *Server) handleX11Forward(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) (err error) {
	event := &apievents.X11Forward{
		Metadata: apievents.Metadata{
			Type: events.X11ForwardEvent,
			Code: events.X11ForwardCode,
		},
		UserMetadata: apievents.UserMetadata{
			Login:        ctx.Identity.Login,
			User:         ctx.Identity.TeleportUser,
			Impersonator: ctx.Identity.Impersonator,
		},
		ConnectionMetadata: apievents.ConnectionMetadata{
			LocalAddr:  ctx.ServerConn.LocalAddr().String(),
			RemoteAddr: ctx.ServerConn.RemoteAddr().String(),
		},
		Status: apievents.Status{
			Success: true,
		},
	}

	defer func() {
		if err != nil {
			event.Metadata.Code = events.X11ForwardFailureCode
			event.Status.Success = false
			event.Status.Error = err.Error()
		}
		if trace.IsAccessDenied(err) {
			// denied X11 requests are ok from a protocol perspective so we
			// don't return them, just reply over ssh and emit the audit log.
			s.replyError(ch, req, err)
			err = nil
		}
		if err := s.EmitAuditEvent(s.ctx, event); err != nil {
			log.WithError(err).Warn("Failed to emit x11-forward event.")
		}
	}()

	// check if X11 forwarding is disabled, or if xauth can't be handled.
	if !s.x11.Enabled || x11.CheckXAuthPath() != nil {
		return trace.AccessDenied("X11 forwarding is not enabled")
	}

	// Check if the user's RBAC role allows X11 forwarding.
	if err := s.authHandlers.CheckX11Forward(ctx); err != nil {
		return trace.Wrap(err)
	}

	var x11Req x11.ForwardRequestPayload
	if err := ssh.Unmarshal(req.Payload, &x11Req); err != nil {
		return trace.Wrap(err)
	}

	if err := ctx.OpenXServerListener(x11Req, s.x11.DisplayOffset, s.x11.MaxDisplay); err != nil {
		if trace.IsLimitExceeded(err) {
			return trace.AccessDenied("The server cannot support any more X11 forwarding sessions at this time")
		}
		return trace.Wrap(err)
	}

	return nil
}

func (s *Server) handleSubsystem(ctx context.Context, ch ssh.Channel, req *ssh.Request, serverContext *srv.ServerContext) error {
	sb, err := s.parseSubsystemRequest(req, serverContext)
	if err != nil {
		serverContext.Warnf("Failed to parse subsystem request: %v: %v.", req, err)
		return trace.Wrap(err)
	}
	serverContext.Debugf("Subsystem request: %v.", sb)
	// starting subsystem is blocking to the client,
	// while collecting its result and waiting is not blocking
	if err := sb.Start(ctx, serverContext.ServerConn, ch, req, serverContext); err != nil {
		serverContext.Warnf("Subsystem request %v failed: %v.", sb, err)
		serverContext.SendSubsystemResult(srv.SubsystemResult{Err: trace.Wrap(err)})
		return trace.Wrap(err)
	}
	go func() {
		err := sb.Wait()
		log.Debugf("Subsystem %v finished with result: %v.", sb, err)
		serverContext.SendSubsystemResult(srv.SubsystemResult{Err: trace.Wrap(err)})
	}()
	return nil
}

// handleEnv accepts environment variables sent by the client and stores them
// in connection context
func (s *Server) handleEnv(ch ssh.Channel, req *ssh.Request, ctx *srv.ServerContext) error {
	var e sshutils.EnvReqParams
	if err := ssh.Unmarshal(req.Payload, &e); err != nil {
		ctx.Error(err)
		return trace.Wrap(err, "failed to parse env request")
	}
	ctx.SetEnv(e.Name, e.Value)
	return nil
}

// handleKeepAlive accepts and replies to keepalive@openssh.com requests.
func (s *Server) handleKeepAlive(req *ssh.Request) {
	log.Debugf("Received %q: WantReply: %v", req.Type, req.WantReply)

	// only reply if the sender actually wants a response
	if req.WantReply {
		err := req.Reply(true, nil)
		if err != nil {
			log.Warnf("Unable to reply to %q request: %v", req.Type, err)
			return
		}
	}

	log.Debugf("Replied to %q", req.Type)
}

// handleRecordingProxy responds to global out-of-band with a bool which
// indicates if it is in recording mode or not.
func (s *Server) handleRecordingProxy(req *ssh.Request) {
	var recordingProxy bool

	log.Debugf("Global request (%v, %v) received", req.Type, req.WantReply)

	if req.WantReply {
		// get the cluster config, if we can't get it, reply false
		recConfig, err := s.authService.GetSessionRecordingConfig(s.ctx)
		if err != nil {
			err := req.Reply(false, nil)
			if err != nil {
				log.Warnf("Unable to respond to global request (%v, %v): %v", req.Type, req.WantReply, err)
			}
			return
		}

		// reply true that we were able to process the message and reply with a
		// bool if we are in recording mode or not
		recordingProxy = services.IsRecordAtProxy(recConfig.GetMode())
		err = req.Reply(true, []byte(strconv.FormatBool(recordingProxy)))
		if err != nil {
			log.Warnf("Unable to respond to global request (%v, %v): %v: %v", req.Type, req.WantReply, recordingProxy, err)
			return
		}
	}

	log.Debugf("Replied to global request (%v, %v): %v", req.Type, req.WantReply, recordingProxy)
}

// handleVersionRequest replies with the Teleport version of the server.
func (s *Server) handleVersionRequest(req *ssh.Request) {
	err := req.Reply(true, []byte(teleport.Version))
	if err != nil {
		log.Debugf("Failed to reply to version request: %v.", err)
	}
}

// handleProxyJump handles ProxyJump request that is executed via direct tcp-ip dial on the proxy
func (s *Server) handleProxyJump(ctx context.Context, ccx *sshutils.ConnectionContext, identityContext srv.IdentityContext, ch ssh.Channel, req sshutils.DirectTCPIPReq) {
	// Create context for this channel. This context will be closed when the
	// session request is complete.
	ctx, scx, err := srv.NewServerContext(ctx, ccx, s, identityContext)
	if err != nil {
		log.WithError(err).Error("Unable to create connection context.")
		writeStderr(ch, "Unable to create connection context.")
		if err := ch.Close(); err != nil {
			log.WithError(err).Warn("Failed to close channel.")
		}
		return
	}
	scx.IsTestStub = s.isTestStub
	scx.AddCloser(ch)
	defer scx.Close()

	ch = scx.TrackActivity(ch)

	recConfig, err := s.GetAccessPoint().GetSessionRecordingConfig(ctx)
	if err != nil {
		log.Errorf("Unable to fetch session recording config: %v.", err)
		writeStderr(ch, "Unable to fetch session recording configuration.")
		return
	}

	// force agent forward, because in recording mode proxy needs
	// client's agent to authenticate to the target server
	//
	// When proxy is in "Recording mode" the following will happen with SSH:
	//
	// $ ssh -J user@teleport.proxy:3023 -p 3022 user@target -F ./forward.config
	//
	// Where forward.config enables agent forwarding:
	//
	// Host teleport.proxy
	//     ForwardAgent yes
	//
	// This will translate to ProxyCommand:
	//
	// exec ssh -l user -p 3023 -F ./forward.config -vvv -W 'target:3022' teleport.proxy
	//
	// -W means establish direct tcp-ip, and in SSH 2.0 session implementation,
	// this gets called before agent forwarding is requested:
	//
	// https://github.com/openssh/openssh-portable/blob/master/ssh.c#L1884
	//
	// so in recording mode, proxy is forced to request agent forwarding
	// "out of band", before SSH client actually asks for it
	// which is a hack, but the only way we can think of making it work,
	// ideas are appreciated.
	if services.IsRecordAtProxy(recConfig.GetMode()) {
		err = s.handleAgentForwardProxy(&ssh.Request{}, scx)
		if err != nil {
			log.Warningf("Failed to request agent in recording mode: %v", err)
			writeStderr(ch, "Failed to request agent")
			return
		}
	}

	netConfig, err := s.GetAccessPoint().GetClusterNetworkingConfig(ctx)
	if err != nil {
		log.Errorf("Unable to fetch cluster networking config: %v.", err)
		writeStderr(ch, "Unable to fetch cluster networking configuration.")
		return
	}

	// The keep-alive loop will keep pinging the remote server and after it has
	// missed a certain number of keep-alive requests it will cancel the
	// closeContext which signals the server to shutdown.
	go srv.StartKeepAliveLoop(srv.KeepAliveParams{
		Conns: []srv.RequestSender{
			scx.ServerConn,
		},
		Interval:     netConfig.GetKeepAliveInterval(),
		MaxCount:     netConfig.GetKeepAliveCountMax(),
		CloseContext: ctx,
		CloseCancel:  scx.CancelFunc(),
	})

	subsys, err := newProxySubsys(scx, s, proxySubsysRequest{
		host: req.Host,
		port: fmt.Sprintf("%v", req.Port),
	})
	if err != nil {
		log.Errorf("Unable instantiate proxy subsystem: %v.", err)
		writeStderr(ch, "Unable to instantiate proxy subsystem.")
		return
	}

	if err := subsys.Start(ctx, scx.ServerConn, ch, &ssh.Request{}, scx); err != nil {
		log.Errorf("Unable to start proxy subsystem: %v.", err)
		writeStderr(ch, "Unable to start proxy subsystem.")
		return
	}

	wch := make(chan struct{})
	go func() {
		defer close(wch)
		if err := subsys.Wait(); err != nil {
			log.Errorf("Proxy subsystem failed: %v.", err)
			writeStderr(ch, "Proxy subsystem failed.")
		}
	}()
	select {
	case <-wch:
	case <-ctx.Done():
	}
}

func (s *Server) replyError(ch ssh.Channel, req *ssh.Request, err error) {
	log.Error(err)
	// Terminate the error with a newline when writing to remote channel's
	// stderr so the output does not mix with the rest of the output if the remote
	// side is not doing additional formatting for extended data.
	// See github.com/gravitational/teleport/issues/4542
	message := utils.FormatErrorWithNewline(err)
	writeStderr(ch, message)
	if req.WantReply {
		if err := req.Reply(false, []byte(message)); err != nil {
			log.Warnf("Failed to reply to %q request: %v", req.Type, err)
		}
	}
}

func (s *Server) parseSubsystemRequest(req *ssh.Request, ctx *srv.ServerContext) (srv.Subsystem, error) {
	var r sshutils.SubsystemReq
	if err := ssh.Unmarshal(req.Payload, &r); err != nil {
		return nil, trace.BadParameter("failed to parse subsystem request: %v", err)
	}

	switch {
	case s.proxyMode && strings.HasPrefix(r.Name, "proxy:"):
		return parseProxySubsys(r.Name, s, ctx)
	case s.proxyMode && strings.HasPrefix(r.Name, "proxysites"):
		return parseProxySitesSubsys(r.Name, s)
	case r.Name == sftpSubsystem:
		return newSFTPSubsys()
	default:
		return nil, trace.BadParameter("unrecognized subsystem: %v", r.Name)
	}
}

func writeStderr(ch ssh.Channel, msg string) {
	if _, err := io.WriteString(ch.Stderr(), msg); err != nil {
		log.Warnf("Failed writing to ssh.Channel.Stderr(): %v", err)
	}
}

func rejectChannel(ch ssh.NewChannel, reason ssh.RejectionReason, msg string) {
	if err := ch.Reject(reason, msg); err != nil {
		log.Warnf("Failed to reject new ssh.Channel: %v", err)
	}
}
