// Package ack detects AWS Controllers for Kubernetes (ACK) resources and
// normalizes embedded IAM-style policy documents so declarative controls can
// inspect them uniformly.
package ack

import (
	"strings"
)

// APIGroupSuffix is the common suffix of every ACK controller API group,
// e.g. rds.services.k8s.aws or s3.services.k8s.aws.
const APIGroupSuffix = ".services.k8s.aws"

// IsACKGroup reports whether an API group belongs to an ACK controller.
func IsACKGroup(apiGroup string) bool {
	return strings.HasSuffix(apiGroup, APIGroupSuffix)
}

// ServiceFromGroup extracts the AWS service name from an ACK API group
// ("rds.services.k8s.aws" -> "rds"). Returns "" for non-ACK groups.
func ServiceFromGroup(apiGroup string) string {
	if !IsACKGroup(apiGroup) {
		return ""
	}
	return strings.TrimSuffix(apiGroup, APIGroupSuffix)
}
