/*
Copyright 2022 Gravitational, Inc.
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

package watcher

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/srv/db/common"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

type Action func(context.Context, Operation, *eks.Cluster)

type Watcher struct {
	fetchers []fetcher
	waitTime time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
}

func NewWatcher(
	ctx context.Context,
	matchers []services.AWSMatcher,
	clients common.CloudClients,
	action Action,
	log logrus.FieldLogger,
) (*Watcher, error) {
	cancelCtx, cancelFn := context.WithCancel(ctx)
	watcher := Watcher{
		fetchers: []fetcher{},
		ctx:      cancelCtx,
		cancel:   cancelFn,
		waitTime: time.Minute,
	}
	for _, matcher := range matchers {
		for _, region := range matcher.Regions {
			cl, err := clients.GetAWSEKSClient(region)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			fetcher, err := newEKSClusterFetcher(matcher, region, cl, action, log)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			watcher.fetchers = append(watcher.fetchers, fetcher)
		}
	}
	return &watcher, nil
}

func (w *Watcher) Start() {
	ticker := time.NewTicker(w.waitTime)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			for _, fetcher := range w.fetchers {
				err := fetcher.FetchKubeClusters(w.ctx)
				if err != nil {
					logrus.Error("Failed to fetch EKS clusters: ", err)
				}
			}
		case <-w.ctx.Done():
			return
		}
	}
}

func (w *Watcher) Close() {
	w.cancel()
}

type fetcher interface {
	FetchKubeClusters(context.Context) error
}
