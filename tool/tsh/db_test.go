/*
Copyright 2015-2017 Gravitational, Inc.

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

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gravitational/teleport/api/breaker"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/fixtures"
	"github.com/gravitational/teleport/lib/service"
	"github.com/gravitational/teleport/lib/tlsca"
	"github.com/gravitational/teleport/lib/utils"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
)

// TestDatabaseLogin verifies "tsh db login" command.
func TestDatabaseLogin(t *testing.T) {
	tmpHomePath := t.TempDir()

	connector := mockConnector(t)

	alice, err := types.NewUser("alice@example.com")
	require.NoError(t, err)
	alice.SetRoles([]string{"access"})
	alice.SetTraits(map[string][]string{"db_users": {"*"}, "db_names": {"*"}})

	authProcess, proxyProcess := makeTestServers(t, withBootstrap(connector, alice))
	makeTestDatabaseServer(t, authProcess, proxyProcess, service.Database{
		Name:     "postgres",
		Protocol: defaults.ProtocolPostgres,
		URI:      "localhost:5432",
	}, service.Database{
		Name:     "mongo",
		Protocol: defaults.ProtocolMongoDB,
		URI:      "localhost:27017",
	})

	authServer := authProcess.GetAuthServer()
	require.NotNil(t, authServer)

	proxyAddr, err := proxyProcess.ProxyWebAddr()
	require.NoError(t, err)

	// Log into Teleport cluster.
	err = Run(context.Background(), []string{
		"login", "--insecure", "--debug", "--auth", connector.GetName(), "--proxy", proxyAddr.String(),
	}, setHomePath(tmpHomePath), cliOption(func(cf *CLIConf) error {
		cf.mockSSOLogin = mockSSOLogin(t, authServer, alice)
		return nil
	}))
	require.NoError(t, err)

	// Fetch the active profile.
	profile, err := client.StatusFor(tmpHomePath, proxyAddr.Host(), alice.GetName())
	require.NoError(t, err)

	// Log into test Postgres database.
	err = Run(context.Background(), []string{
		"db", "login", "--debug", "postgres",
	}, setHomePath(tmpHomePath))
	require.NoError(t, err)

	// Verify Postgres identity file contains certificate.
	certs, keys, err := decodePEM(profile.DatabaseCertPathForCluster("", "postgres"))
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.Len(t, keys, 0)

	// Log into test Mongo database.
	err = Run(context.Background(), []string{
		"db", "login", "--debug", "--db-user", "admin", "mongo",
	}, setHomePath(tmpHomePath))
	require.NoError(t, err)

	// Verify Mongo identity file contains both certificate and key.
	certs, keys, err = decodePEM(profile.DatabaseCertPathForCluster("", "mongo"))
	require.NoError(t, err)
	require.Len(t, certs, 1)
	require.Len(t, keys, 1)
}

// TestDatabaseRouteCheck verifies database route checking for "tsh db [login|connect]".
func TestDatabaseRouteCheck(t *testing.T) {
	pgSvcName := "postgres"
	mySvcName := "mysql"
	connector := mockConnector(t)
	authProcess, proxyProcess := makeTestServers(t, withBootstrap(connector))
	makeTestDatabaseServer(t, authProcess, proxyProcess, service.Database{
		Name:     pgSvcName,
		Protocol: defaults.ProtocolPostgres,
		URI:      "localhost:5432",
	}, service.Database{
		Name:     mySvcName,
		Protocol: defaults.ProtocolMySQL,
		URI:      "localhost:3306",
	})

	authServer := authProcess.GetAuthServer()
	require.NotNil(t, authServer)

	proxyAddr, err := proxyProcess.ProxyWebAddr()
	require.NoError(t, err)

	tests := []struct {
		desc         string
		allowUsers   []string
		allowDBNames []string
		denyUsers    []string
		denyDBNames  []string
		svcName      string
		dbUser       string
		dbName       string
		isOk         bool
	}{
		{
			desc:       "denied wildcard db_users is not ok",
			allowUsers: []string{"alice"},
			denyUsers:  []string{"*"},
			svcName:    mySvcName,
			dbUser:     "alice",
			isOk:       false,
		},
		{
			desc:    "no allowed db_users is not ok",
			svcName: mySvcName,
			dbUser:  "alice",
			isOk:    false,
		},
		{
			desc:       "specific db user that is not allowed is not ok",
			allowUsers: []string{"alice"},
			svcName:    mySvcName,
			dbUser:     "bob",
			isOk:       false,
		},
		{
			desc:       "blank db_user with any allowed db_users is ok",
			allowUsers: []string{"foo"},
			svcName:    mySvcName,
			dbUser:     "",
			isOk:       true,
		},
		{
			desc:        "mysql denied wildcard db_names is ok",
			allowUsers:  []string{"alice"},
			denyDBNames: []string{"*"},
			svcName:     mySvcName,
			dbUser:      "alice",
			isOk:        true,
		},
		{
			desc:        "postgres denied wildcard db_names is not ok",
			allowUsers:  []string{"alice"},
			denyDBNames: []string{"*"},
			svcName:     pgSvcName,
			dbUser:      "alice",
			dbName:      "postgres",
			isOk:        false,
		},
		{
			desc:         "mysql with no allowed db_names is ok",
			allowUsers:   []string{"alice"},
			allowDBNames: []string{""},
			svcName:      mySvcName,
			dbUser:       "alice",
			isOk:         true,
		},
		{
			desc:         "postgres with no allowed db_names is not ok",
			allowUsers:   []string{"alice"},
			allowDBNames: []string{""},
			svcName:      pgSvcName,
			dbUser:       "alice",
			dbName:       "postgres",
			isOk:         false,
		},
		{
			desc:         "postgres specific db_name not allowed is not ok",
			allowUsers:   []string{"alice"},
			allowDBNames: []string{"foo"},
			svcName:      pgSvcName,
			dbUser:       "alice",
			dbName:       "postgres",
			isOk:         false,
		},
		{
			desc:         "mysql specific db_name not allowed is ok",
			allowUsers:   []string{"alice"},
			allowDBNames: []string{"foo"},
			svcName:      mySvcName,
			dbUser:       "alice",
			dbName:       "bar", // meaningless db name for mysql, but passing it shouldnt err
			isOk:         true,
		},
		{
			desc:         "postgres blank db_name with any allowed db_names is ok",
			allowUsers:   []string{"alice"},
			allowDBNames: []string{"foo"},
			svcName:      pgSvcName,
			dbUser:       "alice",
			dbName:       "",
			isOk:         true,
		},
	}

	for i, tt := range tests {
		// rebind variable scope for parallel subtests
		i := i
		tt := tt

		// new home dir for each test so they dont race eachother
		tmpHomePath := t.TempDir()

		t.Run(tt.desc, func(t *testing.T) {
			// run table tests in parallel
			t.Parallel()
			userName := fmt.Sprintf("user%v", i)
			user, err := types.NewUser(userName)
			require.NoError(t, err)

			roleName := fmt.Sprintf("role%v", i)
			denierRole, err := types.NewRole(roleName, types.RoleSpecV5{
				Deny: types.RoleConditions{
					Namespaces:    []string{apidefaults.Namespace},
					DatabaseUsers: tt.denyUsers,
					DatabaseNames: tt.denyDBNames,
				},
			})
			require.NoError(t, err)

			user.SetRoles([]string{"access", roleName})
			user.SetTraits(map[string][]string{
				"db_users": tt.allowUsers,
				"db_names": tt.allowDBNames,
			})

			err = authServer.CreateUser(context.TODO(), user)
			require.NoError(t, err)

			err = authServer.UpsertRole(context.TODO(), denierRole)
			require.NoError(t, err)

			// Log into Teleport cluster.
			loginCmd := []string{
				"login",
				"--insecure",
				"--debug",
				"--auth", connector.GetName(),
				"--proxy", proxyAddr.String(),
			}
			err = Run(context.Background(),
				loginCmd,
				setHomePath(tmpHomePath),
				cliOption(func(cf *CLIConf) error {
					cf.mockSSOLogin = mockSSOLogin(t, authServer, user)
					return nil
				}))
			require.NoError(t, err)

			// Log into test database.
			dbLoginCmd := []string{
				"db",
				"login",
				"--debug",
				"--db-user", tt.dbUser,
				"--db-name", tt.dbName,
				tt.svcName,
			}
			err = Run(context.Background(), dbLoginCmd, setHomePath(tmpHomePath))
			if tt.isOk {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}

func TestFormatDatabaseListCommand(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		require.Equal(t, "tsh db ls", formatDatabaseListCommand(""))
	})

	t.Run("with cluster flag", func(t *testing.T) {
		require.Equal(t, "tsh db ls --cluster=leaf", formatDatabaseListCommand("leaf"))
	})
}

func TestFormatConfigCommand(t *testing.T) {
	db := tlsca.RouteToDatabase{
		ServiceName: "example-db",
	}

	t.Run("default", func(t *testing.T) {
		require.Equal(t, "tsh db config --format=cmd example-db", formatDatabaseConfigCommand("", db))
	})

	t.Run("with cluster flag", func(t *testing.T) {
		require.Equal(t, "tsh db config --cluster=leaf --format=cmd example-db", formatDatabaseConfigCommand("leaf", db))
	})
}

func TestDBInfoHasChanged(t *testing.T) {
	tests := []struct {
		name               string
		databaseUserName   string
		databaseName       string
		db                 tlsca.RouteToDatabase
		wantUserHasChanged bool
	}{
		{
			name:             "empty cli database user flag",
			databaseUserName: "",
			db: tlsca.RouteToDatabase{
				Username: "alice",
				Protocol: defaults.ProtocolMongoDB,
			},
			wantUserHasChanged: false,
		},
		{
			name:             "different user",
			databaseUserName: "alice",
			db: tlsca.RouteToDatabase{
				Username: "bob",
				Protocol: defaults.ProtocolMongoDB,
			},
			wantUserHasChanged: true,
		},
		{
			name:             "different user mysql protocol",
			databaseUserName: "alice",
			db: tlsca.RouteToDatabase{
				Username: "bob",
				Protocol: defaults.ProtocolMySQL,
			},
			wantUserHasChanged: true,
		},
		{
			name:             "same user",
			databaseUserName: "bob",
			db: tlsca.RouteToDatabase{
				Username: "bob",
				Protocol: defaults.ProtocolMongoDB,
			},
			wantUserHasChanged: false,
		},
		{
			name:             "empty cli database user and database name flags",
			databaseUserName: "",
			databaseName:     "",
			db: tlsca.RouteToDatabase{
				Username: "alice",
				Protocol: defaults.ProtocolMongoDB,
			},
			wantUserHasChanged: false,
		},
		{
			name:             "different database name",
			databaseUserName: "",
			databaseName:     "db1",
			db: tlsca.RouteToDatabase{
				Username: "alice",
				Database: "db2",
				Protocol: defaults.ProtocolMongoDB,
			},
			wantUserHasChanged: true,
		},
		{
			name:             "same database name",
			databaseUserName: "",
			databaseName:     "db1",
			db: tlsca.RouteToDatabase{
				Username: "alice",
				Database: "db1",
				Protocol: defaults.ProtocolMongoDB,
			},
			wantUserHasChanged: false,
		},
	}

	ca, err := tlsca.FromKeys([]byte(fixtures.TLSCACertPEM), []byte(fixtures.TLSCAKeyPEM))
	require.NoError(t, err)
	privateKey, err := rsa.GenerateKey(rand.Reader, constants.RSAKeySize)
	require.NoError(t, err)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			identity := tlsca.Identity{
				Username:        "user",
				RouteToDatabase: tc.db,
				Groups:          []string{"none"},
			}
			subj, err := identity.Subject()
			require.NoError(t, err)
			certBytes, err := ca.GenerateCertificate(tlsca.CertificateRequest{
				PublicKey: privateKey.Public(),
				Subject:   subj,
				NotAfter:  time.Now().Add(time.Hour),
			})
			require.NoError(t, err)

			certPath := filepath.Join(t.TempDir(), "mongo_db_cert.pem")
			require.NoError(t, os.WriteFile(certPath, certBytes, 0600))

			cliConf := &CLIConf{DatabaseUser: tc.databaseUserName, DatabaseName: tc.databaseName}
			got, err := dbInfoHasChanged(cliConf, certPath)
			require.NoError(t, err)
			require.Equal(t, tc.wantUserHasChanged, got)
		})
	}
}

func makeTestDatabaseServer(t *testing.T, auth *service.TeleportProcess, proxy *service.TeleportProcess, dbs ...service.Database) (db *service.TeleportProcess) {
	// Proxy uses self-signed certificates in tests.
	lib.SetInsecureDevMode(true)

	cfg := service.MakeDefaultConfig()
	cfg.Hostname = "localhost"
	cfg.DataDir = t.TempDir()
	cfg.CircuitBreakerConfig = breaker.NoopBreakerConfig()

	proxyAddr, err := proxy.ProxyWebAddr()
	require.NoError(t, err)

	cfg.AuthServers = []utils.NetAddr{*proxyAddr}
	cfg.Token = proxy.Config.Token
	cfg.SSH.Enabled = false
	cfg.Auth.Enabled = false
	cfg.Databases.Enabled = true
	cfg.Databases.Databases = dbs
	cfg.Log = utils.NewLoggerForTests()

	db, err = service.NewTeleport(cfg)
	require.NoError(t, err)
	require.NoError(t, db.Start())

	t.Cleanup(func() {
		db.Close()
	})

	// Wait for database agent to start.
	eventCh := make(chan service.Event, 1)
	db.WaitForEvent(db.ExitContext(), service.DatabasesReady, eventCh)
	select {
	case <-eventCh:
	case <-time.After(10 * time.Second):
		t.Fatal("database server didn't start after 10s")
	}

	// Wait for all databases to register to avoid races.
	for _, database := range dbs {
		waitForDatabase(t, auth, database)
	}

	return db
}

func waitForDatabase(t *testing.T, auth *service.TeleportProcess, db service.Database) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for {
		select {
		case <-time.After(500 * time.Millisecond):
			all, err := auth.GetAuthServer().GetDatabaseServers(ctx, apidefaults.Namespace)
			require.NoError(t, err)
			for _, a := range all {
				if a.GetName() == db.Name {
					return
				}
			}
		case <-ctx.Done():
			t.Fatal("database not registered after 10s")
		}
	}
}

// decodePEM sorts out specified PEM file into certificates and private keys.
func decodePEM(pemPath string) (certs []pem.Block, keys []pem.Block, err error) {
	bytes, err := os.ReadFile(pemPath)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	var block *pem.Block
	for {
		block, bytes = pem.Decode(bytes)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			certs = append(certs, *block)
		case "RSA PRIVATE KEY":
			keys = append(keys, *block)
		}
	}
	return certs, keys, nil
}
