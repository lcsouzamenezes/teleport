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

// Operation defines the operation
type Operation int

const (
	// OperationCreate is used when a new cluster is discovered
	OperationCreate Operation = iota + 1
	// OperationUpdate is used when a cluster is updated (eg API url, CA or static labels).
	OperationUpdate
	// OperationDelete is used when a cluster is deleted or does not match the target labels.
	OperationDelete
)
