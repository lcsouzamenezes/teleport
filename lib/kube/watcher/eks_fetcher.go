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
	"reflect"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/eks"
	"github.com/aws/aws-sdk-go/service/eks/eksiface"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
)

type eksClusterFetcher struct {
	filterLabels types.Labels
	eksClient    eksiface.EKSAPI
	region       string
	mu           sync.Mutex
	action       Action
	cache        map[string]cacheEntry
	log          logrus.FieldLogger
}

func newEKSClusterFetcher(matcher services.AWSMatcher, region string, eksClient eksiface.EKSAPI, action Action, log logrus.FieldLogger) (*eksClusterFetcher, error) {
	fetcherConfig := eksClusterFetcher{
		eksClient:    eksClient,
		filterLabels: matcher.Tags,
		region:       region,
		cache:        map[string]cacheEntry{},
		action:       action,
		log: log.WithFields(logrus.Fields{
			"discovery": "kube",
			"type":      "eks",
			"region":    region,
		}),
	}

	return &fetcherConfig, nil
}

type cacheEntry struct {
	lastSeen time.Time
	cluster  *eks.Cluster
}

func (f *eksClusterFetcher) FetchKubeClusters(ctx context.Context) error {
	err := f.eksClient.ListClustersPagesWithContext(ctx,
		&eks.ListClustersInput{
			Include: nil, // For now we should only list EKS clusters
		},
		func(clustersList *eks.ListClustersOutput, _ bool) bool {
			wg := &sync.WaitGroup{}
			wg.Add(len(clustersList.Clusters))
			for i := 0; i < len(clustersList.Clusters); i++ {
				go func(eksClusterName *string) {
					defer wg.Done()
					logger := f.log.WithField("cluster_name", *eksClusterName)
					rsp, err := f.eksClient.DescribeClusterWithContext(
						ctx,
						&eks.DescribeClusterInput{
							Name: eksClusterName,
						},
					)
					if err != nil {
						logger.WithError(err).Warnf("Unable to describe EKS cluster: %v", err)
						return
					}
					cluster := rsp.Cluster

					clusterLabels := f.eksTagsToLabels(cluster.Tags)

					if match, reason, err := services.MatchLabels(f.filterLabels, clusterLabels); err != nil {
						logger.WithError(err).Warnf("Unable to match EKS cluster labels against match labels: %v", err)
						return
					} else if !match {
						f.mu.Lock()
						defer f.mu.Unlock()
						if _, ok := f.cache[*eksClusterName]; !ok {
							logger.Debugf("EKS cluster labels does not match the selector: %s", reason)
						} else {
							delete(f.cache, *eksClusterName)
							f.action(ctx, OperationDelete, cluster)
						}
						return
					}

					// delete is triggered by other operation
					var operation Operation
					f.mu.Lock()
					switch *cluster.Status {
					case eks.ClusterStatusCreating, eks.ClusterStatusPending, eks.ClusterStatusFailed:
						logger.Debugf("EKS cluster not ready: status=%s", *cluster.Status)
						return
					case eks.ClusterStatusActive, eks.ClusterStatusUpdating:
						if entry, ok := f.cache[*eksClusterName]; ok {
							// todo: validate the equality for eks clusters: endpoints + labels + CA
							if reflect.DeepEqual(entry.cluster, cluster) {
								// eks cluster has the same config as before.
								// doing nothing and returning early since we do not need to update it.
								return
							}
							operation = OperationUpdate
						} else {
							operation = OperationCreate
						}

						f.cache[*eksClusterName] = cacheEntry{
							lastSeen: time.Now(),
							cluster:  cluster,
						}
					case eks.ClusterStatusDeleting:
						operation = OperationDelete
						// clear object from cache
						delete(f.cache, *eksClusterName)
					}
					f.mu.Unlock()
					f.action(ctx, operation, cluster)
				}(clustersList.Clusters[i])
			}
			wg.Wait()
			return true
		},
	)

	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.cache {
		//  todo: fix this shiiit
		if v.lastSeen.Before(time.Now().Add(-3 * time.Minute)) {
			delete(f.cache, k)
			f.action(ctx, OperationDelete, v.cluster)
		}
	}

	return trace.Wrap(err)

}

func (f *eksClusterFetcher) eksTagsToLabels(tags map[string]*string) map[string]string {
	labels := make(map[string]string)
	for key, valuePtr := range tags {
		if types.IsValidLabelKey(key) {
			labels[key] = aws.StringValue(valuePtr)
		} else {
			f.log.Debugf("Skipping EKS tag %q, not a valid label key", key)
		}
	}
	return labels
}
