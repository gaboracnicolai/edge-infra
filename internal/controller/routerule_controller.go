package controller

import (
	"context"
	"fmt"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	edgev1alpha1 "github.com/edge-infra/control-plane/internal/controller/api/v1alpha1"
	"github.com/edge-infra/control-plane/internal/store"
)

// RouteRuleReconciler reconciles edge.io/v1alpha1 RouteRule CRs into the
// configuration store, then asks the xDS reconciler to push a new snapshot.
type RouteRuleReconciler struct {
	// Client is the controller-runtime client used to read/write CRs.
	Client client.Client
	// Scheme is the runtime scheme registered with the manager.
	Scheme *runtime.Scheme
	// Store persists the desired RouteRule state.
	Store store.Store
	// Trigger requests an immediate xDS reconcile after a mutation.
	Trigger Trigger
}

// Reconcile implements reconcile.Reconciler.
func (r *RouteRuleReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := ctrl.LoggerFrom(ctx).WithValues("routerule", req.NamespacedName)

	var rr edgev1alpha1.RouteRule
	if err := r.Client.Get(ctx, req.NamespacedName, &rr); err != nil {
		if apierrors.IsNotFound(err) {
			// Deletion is handled via the finalizer path so we have the gateway
			// and path prefix available; a bare NotFound here is a no-op.
			return ctrl.Result{}, nil
		}
		return ctrl.Result{}, err
	}

	if !rr.DeletionTimestamp.IsZero() {
		if err := r.Store.DeleteRoute(ctx, rr.Spec.GatewayRef, rr.Spec.PathPrefix); err != nil {
			log.Error(err, "delete route on deletion timestamp")
			return ctrl.Result{RequeueAfter: requeueOnError}, err
		}
		r.Trigger.TriggerNow()
		if controllerutil.RemoveFinalizer(&rr, edgev1alpha1.ControllerFinalizer) {
			if err := r.Client.Update(ctx, &rr); err != nil {
				return ctrl.Result{}, err
			}
		}
		return ctrl.Result{}, nil
	}

	if controllerutil.AddFinalizer(&rr, edgev1alpha1.ControllerFinalizer) {
		if err := r.Client.Update(ctx, &rr); err != nil {
			return ctrl.Result{}, err
		}
	}

	timeout := int(rr.Spec.TimeoutSeconds)
	if timeout <= 0 {
		timeout = 30
	}
	domain := store.Route{
		Name:           rr.Name,
		GatewayName:    rr.Spec.GatewayRef,
		Hosts:          rr.Spec.Hostnames,
		PathPrefix:     rr.Spec.PathPrefix,
		ClusterName:    rr.Spec.ClusterRef,
		TimeoutSeconds: timeout,
	}
	if err := r.Store.UpsertRoute(ctx, domain); err != nil {
		log.Error(err, "upsert route")
		return r.markFailed(ctx, &rr, err)
	}
	r.Trigger.TriggerNow()

	patch := client.MergeFrom(rr.DeepCopy())
	rr.Status.Synced = true
	rr.Status.LastSyncedAt = metav1.Now()
	if err := r.Client.Status().Patch(ctx, &rr, patch); err != nil {
		return ctrl.Result{}, fmt.Errorf("patch status: %w", err)
	}
	return ctrl.Result{}, nil
}

func (r *RouteRuleReconciler) markFailed(ctx context.Context, rr *edgev1alpha1.RouteRule, cause error) (ctrl.Result, error) {
	patch := client.MergeFrom(rr.DeepCopy())
	rr.Status.Synced = false
	rr.Status.LastSyncedAt = metav1.Now()
	if perr := r.Client.Status().Patch(ctx, rr, patch); perr != nil {
		return ctrl.Result{RequeueAfter: requeueOnError}, fmt.Errorf("%w (status patch: %v)", cause, perr)
	}
	return ctrl.Result{RequeueAfter: requeueOnError}, cause
}

// SetupWithManager wires this reconciler into the controller-runtime Manager.
func (r *RouteRuleReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&edgev1alpha1.RouteRule{}).
		Complete(r)
}
