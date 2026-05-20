// Package v1alpha1 contains the Go API types for the edge.io API group.
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion identifies the edge.io/v1alpha1 API.
var GroupVersion = schema.GroupVersion{Group: "edge.io", Version: "v1alpha1"}

// SchemeBuilder collects the Go types in this package for scheme registration.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme registers the types defined in this package with a runtime scheme.
var AddToScheme = SchemeBuilder.AddToScheme
