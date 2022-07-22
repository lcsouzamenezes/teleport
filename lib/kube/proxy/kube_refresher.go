/*
Copyright 2018-2022 Gravitational, Inc.

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

package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/transport"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"
)

func (f *Forwarder) removeKubeCluster(name string) error {
	f.rwMutexCreds.Lock()
	if creds, ok := f.creds[name]; ok {
		creds.close()
	}
	delete(f.creds, name)
	f.rwMutexCreds.Unlock()
	f.mu.Lock()
	// close active sessions
	var errs []error
	for _, sess := range f.sessions {
		if sess.ctx.kubeCluster == name {
			// TODO: check if we should sebd errors to client
			errs = append(errs, sess.Close())
		}
	}
	f.mu.Unlock()
	return trace.NewAggregate(errs...)
}

func (f *Forwarder) addKubeCluster(cluster *eks.Cluster) error {
	dyn, err := newDynamicCreds(cluster, f.getStaticLabels(), f.log)
	if err != nil {
		return trace.Wrap(err)
	}
	f.rwMutexCreds.Lock()
	f.creds[*cluster.Name] = dyn
	f.rwMutexCreds.Unlock()

	return nil
}

func (f *Forwarder) updateKubeCluster(cluster *eks.Cluster) error {
	f.rwMutexCreds.Lock()
	creds, ok := f.creds[*cluster.Name]
	if !ok {
		return fmt.Errorf("cluster %s not found", *cluster.Name)
	}
	f.rwMutexCreds.Unlock()

	dynCreds, ok := creds.(*dynamicKubeCreds)
	if !ok {
		return fmt.Errorf("creds is not *dynamicKubeCreds, instead it is %T", dynCreds)
	}
	return trace.Wrap(dynCreds.updateCluster(cluster))

}

func newDynamicCreds(cluster *eks.Cluster, staticLabels map[string]string, log logrus.FieldLogger) (*dynamicKubeCreds, error) {
	dn := &dynamicKubeCreds{
		eksCluster:          cluster,
		renewTicker:         time.NewTicker(1 * time.Hour), // this will be reseted by renewClientset
		closeC:              make(chan struct{}),
		serviceStaticLabels: staticLabels,
		log:                 log,
	}

	if err := dn.renewClientset(); err != nil {
		return nil, trace.Wrap(err)
	}

	go func() {
		select {
		case <-dn.closeC:
			dn.closeC <- struct{}{}
			return
		case <-dn.renewTicker.C:
			if err := dn.renewClientset(); err != nil {
				// TODO: add loggs
				_ = err
			}
		}
	}()
	return dn, nil
}

type dynamicKubeCreds struct {
	eksCluster          *eks.Cluster
	renewTicker         *time.Ticker
	st                  *staticKubeCreds
	serviceStaticLabels map[string]string
	log                 logrus.FieldLogger
	sync.RWMutex
	closeC chan struct{}
}

func (c *dynamicKubeCreds) close() error {
	c.Lock()
	defer c.Unlock()
	c.closeC <- struct{}{}
	<-c.closeC
	return nil
}

func (d *dynamicKubeCreds) tlsConfiguration() *tls.Config {
	d.RLock()
	defer d.RUnlock()
	return d.st.tlsConfig
}
func (d *dynamicKubeCreds) transportConfiguration() *transport.Config {
	d.RLock()
	defer d.RUnlock()
	return d.st.transportConfig
}
func (d *dynamicKubeCreds) targetAddress() string {
	d.RLock()
	defer d.RUnlock()
	return d.st.targetAddr
}
func (d *dynamicKubeCreds) kubernetesClient() *kubernetes.Clientset {
	d.RLock()
	defer d.RUnlock()
	return d.st.kubeClient
}
func (d *dynamicKubeCreds) wrapTransport(rt http.RoundTripper) (http.RoundTripper, error) {
	d.RLock()
	defer d.RUnlock()
	return d.st.wrapTransport(rt)
}

func (d *dynamicKubeCreds) getStaticLabels() map[string]string {
	d.RLock()
	defer d.RUnlock()
	return d.st.staticLabels
}

func (d *dynamicKubeCreds) updateCluster(cluster *eks.Cluster) error {
	d.RLock()
	d.eksCluster = cluster
	d.RUnlock()
	return trace.Wrap(d.renewClientset())
}

func (d *dynamicKubeCreds) renewClientset() error {
	gen, err := token.NewGenerator(true, false)
	if err != nil {
		return trace.Wrap(err)
	}
	opts := &token.GetTokenOptions{
		ClusterID: aws.StringValue(d.eksCluster.Name),
	}
	tok, err := gen.GetWithOptions(opts)
	if err != nil {
		return trace.Wrap(err)
	}
	ca, err := base64.StdEncoding.DecodeString(aws.StringValue(d.eksCluster.CertificateAuthority.Data))
	if err != nil {
		return trace.Wrap(err)
	}

	creds, err := extractKubeCreds(
		context.TODO(),
		*d.eksCluster.Name,
		&rest.Config{
			Host:        aws.StringValue(d.eksCluster.Endpoint),
			BearerToken: tok.Token,
			TLSClientConfig: rest.TLSClientConfig{
				CAData: ca,
			},
		},
		KubeService,
		"",
		d.log,
		checkImpersonationPermissions,
		nil,
	)
	if err != nil {
		return trace.Wrap(err)
	}

	d.Lock()
	defer d.Unlock()
	d.st = creds
	d.genStaticLabelsFromEKS()
	d.renewTicker.Reset(time.Until(tok.Expiration) / 2)
	return nil
}

func (d *dynamicKubeCreds) genStaticLabelsFromEKS() {
	labels := d.eksTagsToLabels(d.eksCluster.Tags)
	for k, v := range d.serviceStaticLabels {
		labels[k] = v
	}
	labels[types.OriginLabel] = types.OriginCloud
	d.st.staticLabels = labels
}
func (d *dynamicKubeCreds) eksTagsToLabels(tags map[string]*string) map[string]string {
	labels := make(map[string]string)
	for key, valuePtr := range tags {
		if types.IsValidLabelKey(key) {
			labels[key] = aws.StringValue(valuePtr)
		} else {
			//f.log.Debugf("Skipping EKS tag %q, not a valid label key", key)
			// TODO: log here
		}
	}
	return labels
}
