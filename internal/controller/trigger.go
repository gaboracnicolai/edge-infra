// Package controller wires Kubernetes Custom Resources for edge.io into the
// snapshot store and notifies the xDS reconciler when state changes.
package controller

// Trigger requests an out-of-band xDS reconcile. The xds.Reconciler satisfies
// this interface; tests inject fakes that record invocations.
type Trigger interface {
	TriggerNow()
}
